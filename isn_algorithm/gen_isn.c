#include <stdio.h>
#include <malloc.h>
#include <linux/types.h>
#include <string.h>
#include <openssl/md5.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "md5.h"

/* Borrowed from the kernel, be lame and do it in software ;) */
#define ___constant_swab32(x) ((__u32)(                         \
        (((__u32)(x) & (__u32)0x000000ffUL) << 24) |            \
        (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |            \
        (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |            \
        (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#define ___constant_swab16(x) ((__u16)(                         \
        (((__u16)(x) & (__u16)0x00ffU) <<  8) |                 \
        (((__u16)(x) & (__u16)0xff00U) >>  8)))

#define __swab32(x)		___constant_swab32(x)
#define __swab16(x)		___constant_swab16(x)

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __be32_to_cpu(x)	__swab32((__u32)(__be32)(x))
#define __be16_to_cpu(x)	__swab16((__u16)(__be16)(x))
#define __cpu_to_be32(x)	__swab32((__u32)(__be32)(x))
#else
#define __be32_to_cpu(x)	(x)
#define __be16_to_cpu(x)	(x)
#define __cpu_to_be32(x)	(x)
#endif

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __le32_to_cpu(x)	__swab32((__u32)(__le32)(x))
#define __le16_to_cpu(x)	__swab16((__u16)(__le16)(x))
#else
#define __le32_to_cpu(x)	(x)
#define __le16_to_cpu(x)	(x)
#endif

#define __le32_to_be32(x)	__swab32(x)
#define __be32_to_le32(x)	__swab32(x)

#define be32_to_cpu		__be32_to_cpu
#define le32_to_cpu		__le32_to_cpu
#define be16_to_cpu		__be16_to_cpu
#define le16_to_cpu		__le16_to_cpu
#define cpu_to_be32		__cpu_to_be32

#define le32_to_be32		__le32_to_be32
#define be32_to_le32		__be32_to_le32

__u8 quiet = 0;

#define output(...) \
	if (!quiet) printf(__VA_ARGS__); 

__be32 stealth_generic_sequence_number(const __be32 *daddr, const size_t daddr_size,
				      __be16 dport, __u8 *secret, __be16 ih,
				      __be32 tsval)
{
	__be32 iv[MD5_DIGEST_WORDS] = { 0 };
	__be16 *iv_u16ptr = (__be16 *)&iv[0];
	__u8   *iv_ptr = (__u8 *)iv;
	__be32 *av = iv;
	__u32  sec[MD5_MESSAGE_BYTES / sizeof(__u32)];
	__u32 i;

	if (daddr_size > MD5_DIGEST_WORDS * sizeof(__u32)) return 0;

	memcpy(iv, (const __u8 *)daddr, daddr_size);
	output("IV[0:15]  <= daddr[0:%d] = ", daddr_size - 1);
	for (i = 0; i < MD5_DIGEST_WORDS * 4; i++)
		output("\\x%02x", iv_ptr[i]);

	output("\n");

	output("IV[4:5]   <= IV[4:5] xor IH[0:1] =\n");
	output("             = 0x%04x xor 0x%04x =\n", ntohs(iv_u16ptr[2]), ntohs(ih));
	iv_u16ptr[2] ^= ih;
	output("             = 0x%04x\n", ntohs(iv_u16ptr[2]));
	output("IV[8:11]  <= IV[8:11] xor TSVal =\n");
	output("             = 0x%08x xor 0x%08x =\n", ntohl(iv[2]), ntohl(tsval));
	iv[2] ^= tsval;
	output("             = 0x%08x\n", ntohl(iv[2]));
	output("IV[12:13] <= IV[12:13] xor dport =\n");
	output("             = 0x%04x xor 0x%04x =\n", ntohs(iv[3]), ntohs(dport));
	iv_u16ptr[6] ^= dport;
	output("             = 0x%04x\n", ntohs(iv_u16ptr[6]));

	output("AV[0:15]  <= MD5Transform(\"");
	for (i = 0; i < MD5_DIGEST_WORDS * 4; i++) {
		output("\\x%02x", iv_ptr[i]);
	}
	output("\", \n                          \"");
	for (i = 0; i < MD5_MESSAGE_BYTES; i++) {
		output("\\x%02x", secret[i]);
		if (i && !((i + 1) % 8)) output("\" \\\n                          \"");
	}
	output("\") = \n             = ");


	for (i = 0; i < MD5_DIGEST_WORDS; i++)
		iv[i] = le32_to_cpu(iv[i]);
	for (i = 0; i < MD5_MESSAGE_BYTES / sizeof(__u32); i++)
		sec[i] = le32_to_cpu(((__le32 *)secret)[i]);

	md5_transform((__u32 *)iv, (const __u32 *)sec);

	for (i = 0; i < MD5_DIGEST_WORDS; i++) {
		output("%08x", iv[i]);
	}
	output("\n");

	output("AV[0:3]   <= ");
	output("0x%08x ", av[0]);
	av[0] = cpu_to_be32(av[0]);
	for (i = 1; i < MD5_DIGEST_WORDS; i++) {
		output("xor 0x%08x ", av[i]);
		av[0] ^= cpu_to_be32(av[i]);
	}
	output("=\n             = 0x%08x\n", be32_to_cpu(av[0]));

	return av[0];
}

__be32 stealth_tcpv6_sequence_number(const __be32 *daddr, __be16 dport,
				    __u8 *secret, __be16 integrity, __be32 tsval)
{
	return stealth_generic_sequence_number(daddr, 16, dport, secret,
					       integrity, tsval);
}

__be32 stealth_tcp_sequence_number(const __be32 daddr, __be16 dport,
				  __u8 *secret, __be16 integrity, __be32 tsval)
{
	return stealth_generic_sequence_number(&daddr, 4, dport, secret,
					       integrity, tsval);
}

int tcp_stealth_integrity(__be16 *hash, __u8 *secret, __u8 *payload, size_t len)
{
	char data[64 + len];
	__be16 md[MD5_DIGEST_WORDS * 2];
	__u8 *digest = (__u8 *)&md[0];
	int i;
	char *d = data;

	memcpy(data, secret, 64);
	memcpy(data + 64, payload, len);

	output("I[0:15]   <= MD5(\"");
	for (i = 0; i < 64 + len; i++) {
		output("\\x%02x", d[i]);
		if (i + 1 && !((i + 1) % 8)) output("\" \\\n                 \"");
	}
	output("\") = \n             = ");

	MD5(data, 64 + len, (unsigned char *)md);

	for (i = 0; i < MD5_DIGEST_WORDS * 4; i++)
		output("%02x", *(digest + i));

	output("\n");

	output("IH[0:1]   <= ");

	output("0x%04x ", ntohs(md[0]));
	*hash = md[0];
	for (i = 1; i < MD5_DIGEST_WORDS * 2; i++) {
		output("xor 0x%04x ", be16_to_cpu(md[i]));
		*hash ^= md[i];
	}

	output("=\n             = 0x%04x\n", be16_to_cpu(*hash));

	return 0;
}

int main(int argc, char **argv)
{
	__u32 isn;
	__be16 ih = 0;
	__be32 av;

	// version daddr dport tsval secret len payload
	
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;

	if (argc < 5) return -1;

	int version = atoi(argv[1]);
	switch (version) {
	case 4:
		inet_pton(AF_INET, argv[2], &addr.sin_addr);
	break;
	case 6:
		inet_pton(AF_INET6, argv[2], &addr6.sin6_addr);
	break;
	default:
		return -1;
	}

	__u16 dport = atoi(argv[3]);
	__u32 tsval = strtoul(argv[4], NULL, 16);

	__u8 secret[64];
	memcpy(secret, argv[5], strlen(argv[5]) > 64 ? 64 : strlen(argv[5]));
	memset(secret + strlen(argv[5]), 0x00, 64 - strlen(argv[5]));

	__u8 *payload;
	__u32 len = 0;

	if (argc >= 8) {
		payload = argv[7];
		len = atoi(argv[6]);
		if (len > strlen(payload)) len = strlen(payload);
		if (argc == 9 && argv[8][0] == 'q') quiet = 1;
	} else {
		if (argc == 7 && argv[6][0] == 'q') quiet = 1;
	}





	printf("--------------------------------------------------\n");
	printf("------------ ISN Generation Algorithm ------------\n");
	printf("--------------------------------------------------\n");
	printf("Values used for this example:\n");
	printf("--------------------------------------------------\n");
	printf("Destination IP:   %s\n", argv[2]);
	printf("Destination Port: %d\n", dport);
	printf("TSVal:            %08x\n", tsval);
	printf("Secret:           %s\n", secret);

	if (len > 0) {
		printf("Payload:          %s\n", payload);
		printf("Len:              %d\n", len);
		printf("--------------------------------------------------\n");
		tcp_stealth_integrity(&ih, secret, payload, len);
		if (version == 4)
			av = stealth_tcp_sequence_number(addr.sin_addr.s_addr, htons(dport),
							 secret, ih, htonl(tsval));
		if (version == 6)
			av = stealth_tcpv6_sequence_number(
				(const __be32 *)addr6.sin6_addr.s6_addr,
				htons(dport), secret, ih, htonl(tsval));
		__u32 write_seq;
		((__be16 *)&write_seq)[0] = *(__be16 *)&av;
		((__be16 *)&write_seq)[1] = ih;

		write_seq = be32_to_cpu(write_seq);
		printf("--------------------------------------------------\n");
		printf("Resulting Knock ISN (INT+AUTH): 0x%08x\n", write_seq);
		printf("--------------------------------------------------\n");
	} else {
		printf("--------------------------------------------------\n");
		if (version == 4)
			av = stealth_tcp_sequence_number(addr.sin_addr.s_addr, htons(dport),
							 secret, 0, htonl(tsval));
		if (version == 6)
			av = stealth_tcpv6_sequence_number(
				(const __be32 *)addr6.sin6_addr.s6_addr,
				htons(dport), secret, 0, htonl(tsval));
		printf("--------------------------------------------------\n");
		printf("Resulting Knock ISN (AUTH):     0x%08x\n", be32_to_cpu(av));
		printf("--------------------------------------------------\n");
	}
	
	//md5_exp();

	return 0;
}

/* Ignore me, this is just to prove that md5_transform indeed performs a MD5
 * calculation */
int md5_exp()
{
	__u32 append[MD5_MESSAGE_BYTES / sizeof(__u32)] = { 0 };
	__u32 d_cpu[MD5_MESSAGE_BYTES / sizeof(__u32)];
	__u32 iv_cpu[MD5_DIGEST_WORDS * 4];
	__u32 i;
	__u8 *d;
	__u8 *iv;
	__u32 *d_u32ptr;
	__u32 *iv_u32ptr;

	d = malloc(MD5_MESSAGE_BYTES);
	d_u32ptr = (__u32 *)d;
	iv = malloc(MD5_DIGEST_WORDS * 4);
	iv_u32ptr = (__u32 *)iv;

#define IV "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
#define D "0123012301230123012301230123012301230123012301230123012301230123"
	memcpy(iv, IV, MD5_DIGEST_WORDS * 4);
	memcpy(d, D, MD5_MESSAGE_BYTES);

	append[0] = 0x00000080;
	append[14] = 64 << 3;
	append[15] = 64 >> 29;

	for (i = 0; i < MD5_MESSAGE_BYTES / sizeof(__u32); i++) {
		d_cpu[i] = le32_to_cpu(d_u32ptr[i]);
	}
	for (i = 0; i < MD5_DIGEST_WORDS; i++) {
		iv_cpu[i] = le32_to_cpu(iv_u32ptr[i]);
	}

	md5_transform(iv_cpu, d_cpu);

	for (i = 0; i < MD5_DIGEST_WORDS; i++)
		output("%08x", iv_cpu[i]);

	output("\n");

	md5_transform(iv_cpu, append);

	for (i = 0; i < MD5_DIGEST_WORDS; i++)
		iv_cpu[i] = le32_to_be32(iv_cpu[i]);

	/* Final hash is reversed */
	for (i = 0; i < MD5_DIGEST_WORDS; i++)
		output("%08x", iv_cpu[i]);

	output("\n");

	MD5(d, MD5_MESSAGE_BYTES, (unsigned char *)iv);

	for (i = 0; i < MD5_DIGEST_WORDS * 4; i++)
		output("%02x", iv[i]);

	output("\n");

	free(d);
	free(iv);
}
