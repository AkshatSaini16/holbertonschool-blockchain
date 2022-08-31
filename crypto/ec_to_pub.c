#include "hblk_crypto.h"

/**
 * ec_to_pub - a function that converts an EC key to a public key.
 * @key: s a pointer to the EC_KEY structure to retrieve
 * the public key from. If it is NULL, your function must do nothing and fail
 * @pub:is the address at which to store
 * the extracted public key (The key shall not be compressed)
 * Return: pointer to public key, NULL on error
 **/
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN])
{
	const EC_POINT *point;

	if (key == NULL)
		return (NULL);

	point = EC_KEY_get0_public_key(key);
	EC_POINT_point2oct(EC_KEY_get0_group(key), point,
			POINT_CONVERSION_UNCOMPRESSED, pub, EC_PUB_LEN, NULL);

	return (pub);
}
