#include "hblk_crypto.h"

/**
 * ec_verify - Verify an ECDSA signature
 * @key: pointer to the public key to be used to verify the signature
 * @msg: points to the msglen characters to verify the signature
 * @msglen: length of the message to verify
 * @sig: pointer to the signature structure
 * Return: 1 if the signature is valid, 0 otherwise.
 */
int ec_verify(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t const *sig)
{
	if (key == NULL || msg == NULL || sig == NULL)
		return (0);
	return (ECDSA_verify(0, msg, msglen, sig->sig,
						sig->len, (EC_KEY *)key) == 1);
}
