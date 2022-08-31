#include "hblk_crypto.h"

/**
 * EC_KEY *ec_create - a function to create a new EC key pair.
 * Return:return a pointer to an EC_KEY structure,
 * containing both the public and private keys,
 * or NULL upon failure
 **/
EC_KEY *ec_create(void)
{
	EC_KEY *key;

	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!key)
		return (NULL);

	if (!EC_KEY_generate_key(key))
	{
		EC_KEY_free(key);
		return (NULL);
	}

	return (key);
}
