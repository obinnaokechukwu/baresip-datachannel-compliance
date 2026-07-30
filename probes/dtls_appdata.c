/*
 * External libre DTLS application-data proof.
 *
 * This probe is intentionally outside the libre and baresip repositories.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <re.h>

static const uint8_t payload[] = {
	0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x42
};

struct proof {
	struct dtls_sock *client_sock;
	struct dtls_sock *server_sock;
	struct tls_conn *client_conn;
	struct tls_conn *server_conn;
	struct tls *tls;
	struct tmr timeout;
	unsigned client_established;
	unsigned server_established;
	unsigned server_received;
	unsigned client_received;
	int err;
};

static void fail(struct proof *proof, int err)
{
	if (!proof->err)
		proof->err = err ? err : EPROTO;
	re_cancel();
}

static void timeout(void *arg)
{
	struct proof *proof = arg;

	fail(proof, ETIMEDOUT);
}

static int upper_layer_input(struct mbuf *mb)
{
	if (mbuf_get_left(mb) != sizeof(payload))
		return EBADMSG;
	if (memcmp(mbuf_buf(mb), payload, sizeof(payload)))
		return EBADMSG;
	return 0;
}

static void client_receive(struct mbuf *mb, void *arg)
{
	struct proof *proof = arg;
	int err;

	++proof->client_received;
	err = upper_layer_input(mb);
	if (err) {
		fail(proof, err);
		return;
	}

	re_cancel();
}

static void server_receive(struct mbuf *mb, void *arg)
{
	struct proof *proof = arg;
	int err;

	++proof->server_received;

	/*
	 * The upper layer consumes the borrowed mbuf synchronously, exactly as
	 * dc_transport_input() will. The same callback then returns the packet
	 * through DTLS, proving that callback-local mbuf use is safe.
	 */
	err = upper_layer_input(mb);
	if (!err)
		err = dtls_send(proof->server_conn, mb);
	if (err)
		fail(proof, err);
}

static void client_established(void *arg)
{
	struct proof *proof = arg;
	struct mbuf mb = {
		.buf = (uint8_t *)payload,
		.pos = 0,
		.end = sizeof(payload),
		.size = sizeof(payload),
	};
	int err;

	++proof->client_established;
	err = dtls_send(proof->client_conn, &mb);
	if (err)
		fail(proof, err);
}

static void server_established(void *arg)
{
	struct proof *proof = arg;

	++proof->server_established;
}

static void connection_closed(int err, void *arg)
{
	struct proof *proof = arg;

	if (err)
		fail(proof, err);
}

static void incoming_connection(const struct sa *peer, void *arg)
{
	struct proof *proof = arg;
	int err;

	(void)peer;
	if (proof->server_conn) {
		fail(proof, EALREADY);
		return;
	}

	err = dtls_accept(&proof->server_conn, proof->tls,
			  proof->server_sock, server_established,
			  server_receive, connection_closed, proof);
	if (err)
		fail(proof, err);
}

static int run_proof(struct proof *proof)
{
	struct udp_sock *server_udp = NULL;
	struct sa client_address;
	struct sa server_address;
	int err;

	sa_set_str(&client_address, "127.0.0.1", 0);
	sa_set_str(&server_address, "127.0.0.1", 0);

	err = tls_alloc(&proof->tls, TLS_METHOD_DTLS, NULL, NULL);
	if (err)
		goto out;
	err = tls_set_selfsigned_ec(proof->tls, "127.0.0.1", "prime256v1");
	if (err)
		goto out;
	err = udp_listen(&server_udp, &server_address, NULL, NULL);
	if (err)
		goto out;
	err = udp_local_get(server_udp, &server_address);
	if (err)
		goto out;
	err = dtls_listen(&proof->server_sock, NULL, server_udp, 4, 0,
			  incoming_connection, proof);
	if (err)
		goto out;
	err = dtls_listen(&proof->client_sock, &client_address, NULL, 4, 0,
			  NULL, NULL);
	if (err)
		goto out;
	dtls_set_single(proof->client_sock, true);
	err = dtls_connect(&proof->client_conn, proof->tls,
			   proof->client_sock, &server_address,
			   client_established, client_receive,
			   connection_closed, proof);
	if (err)
		goto out;

	tmr_start(&proof->timeout, 2000, timeout, proof);
	err = re_main(NULL);
	tmr_cancel(&proof->timeout);
	if (!err)
		err = proof->err;
	if (!err && (proof->client_established != 1 ||
		     proof->server_established != 1 ||
		     proof->server_received != 1 ||
		     proof->client_received != 1))
		err = EPROTO;

out:
	mem_deref(server_udp);
	return err;
}

int main(void)
{
	struct proof proof = {0};
	int err;

	err = libre_init();
	if (!err)
		err = run_proof(&proof);

	proof.client_conn = mem_deref(proof.client_conn);
	proof.server_conn = mem_deref(proof.server_conn);
	proof.client_sock = mem_deref(proof.client_sock);
	proof.server_sock = mem_deref(proof.server_sock);
	proof.tls = mem_deref(proof.tls);
	libre_close();

	if (err) {
		fprintf(stderr, "DTLS application-data proof failed: %s\n",
			strerror(err));
		return 1;
	}

	printf("{\"verdict\":\"PASS\",\"client_established\":%u,"
	       "\"server_established\":%u,\"server_received\":%u,"
	       "\"client_received\":%u,\"payload_bytes\":%zu}\n",
	       proof.client_established, proof.server_established,
	       proof.server_received, proof.client_received, sizeof(payload));
	return 0;
}
