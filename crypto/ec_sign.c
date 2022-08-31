#include "hblk_crypto.h"

/**
 * ec_sign - Sign a set of bytes with an EC private key
 * @key: pointer to the private key to be used to perform the signature
 * @msg: pointer to the message to sign
 * @msglen: length of the message to sign
 * @sig: holds the address at which to store the signature
 * Return: Your function must return a pointer to
 * the signature buffer upon success (sig->sig)
 * NULL must be returned upon failure
 */
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t *sig)
{
	unsigned int size;

	if (key == NULL || msg == NULL || sig == NULL)
		return (NULL);
	size = sig->len;
	if (ECDSA_sign(0, msg, msglen, sig->sig, &size, (EC_KEY *)key) != 1)
		return (NULL);
	sig->len = size;

	return (sig->sig);
}
