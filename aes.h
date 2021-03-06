/*
 * Copyright (c) 2010, Shanghai Jiao Tong University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the Shanghai Jiao Tong University nor the
 *   names of its contributors may be used to endorse or promote
 *   products derived from this software without specific prior
 *   written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is only an experimental code based on the 32-bit version.
 * It would be more efficient if rewritten for 8-bit platforms.
 *
 * @author Ruowen Wang <rwang9@ncsu.edu>
 * @author Bo Zhu <bo.zhu@uwaterloo.ca>
 * @date   October 14, 2010
 */

#ifndef __AES_H__
#define __AES_H__

// comment this out if used on PC
// #define __UINT_T__

#ifndef __UINT_T__
#define __UINT_T__
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef unsigned long long uint64_t;
#endif /* __UINT_T__ */

#define ROTR(x, y) (((x) >> (y)) | ((x) << (32 - (y))))

static void STORE32B(const uint32_t x, uint8_t *y) {
	const uint8_t *xptr = (uint8_t *)&x;

	*(y    ) = *(xptr + 3);
	*(y + 1) = *(xptr + 2);
	*(y + 2) = *(xptr + 1);
	*(y + 3) = *(xptr    );
}

static void LOAD32B(const uint8_t *y, uint32_t *x) {
	uint8_t *xptr = (uint8_t *)x;

	*(xptr    ) = *(y + 3);
	*(xptr + 1) = *(y + 2);
	*(xptr + 2) = *(y + 1);
	*(xptr + 3) = *(y    );
}

// for little-endian changing from 32 bits to 8 bits
// x is a 32-bit number
#define byte(x, n) (uint32_t)((uint8_t *)&(x))[(n)]

#define Te0(x) TE0[x]
#define Te1(x) ROTR(TE0[x], 8)
#define Te2(x) ROTR(TE0[x], 16)
#define Te3(x) ROTR(TE0[x], 24)

#define Te4_0 0x000000FF & Te4
#define Te4_1 0x0000FF00 & Te4
#define Te4_2 0x00FF0000 & Te4
#define Te4_3 0xFF000000 & Te4

static const uint32_t TE0[256] = {
	0xc66363a5UL, 0xf87c7c84UL, 0xee777799UL, 0xf67b7b8dUL,
	0xfff2f20dUL, 0xd66b6bbdUL, 0xde6f6fb1UL, 0x91c5c554UL,
	0x60303050UL, 0x02010103UL, 0xce6767a9UL, 0x562b2b7dUL,
	0xe7fefe19UL, 0xb5d7d762UL, 0x4dababe6UL, 0xec76769aUL,
	0x8fcaca45UL, 0x1f82829dUL, 0x89c9c940UL, 0xfa7d7d87UL,
	0xeffafa15UL, 0xb25959ebUL, 0x8e4747c9UL, 0xfbf0f00bUL,
	0x41adadecUL, 0xb3d4d467UL, 0x5fa2a2fdUL, 0x45afafeaUL,
	0x239c9cbfUL, 0x53a4a4f7UL, 0xe4727296UL, 0x9bc0c05bUL,
	0x75b7b7c2UL, 0xe1fdfd1cUL, 0x3d9393aeUL, 0x4c26266aUL,
	0x6c36365aUL, 0x7e3f3f41UL, 0xf5f7f702UL, 0x83cccc4fUL,
	0x6834345cUL, 0x51a5a5f4UL, 0xd1e5e534UL, 0xf9f1f108UL,
	0xe2717193UL, 0xabd8d873UL, 0x62313153UL, 0x2a15153fUL,
	0x0804040cUL, 0x95c7c752UL, 0x46232365UL, 0x9dc3c35eUL,
	0x30181828UL, 0x379696a1UL, 0x0a05050fUL, 0x2f9a9ab5UL,
	0x0e070709UL, 0x24121236UL, 0x1b80809bUL, 0xdfe2e23dUL,
	0xcdebeb26UL, 0x4e272769UL, 0x7fb2b2cdUL, 0xea75759fUL,
	0x1209091bUL, 0x1d83839eUL, 0x582c2c74UL, 0x341a1a2eUL,
	0x361b1b2dUL, 0xdc6e6eb2UL, 0xb45a5aeeUL, 0x5ba0a0fbUL,
	0xa45252f6UL, 0x763b3b4dUL, 0xb7d6d661UL, 0x7db3b3ceUL,
	0x5229297bUL, 0xdde3e33eUL, 0x5e2f2f71UL, 0x13848497UL,
	0xa65353f5UL, 0xb9d1d168UL, 0x00000000UL, 0xc1eded2cUL,
	0x40202060UL, 0xe3fcfc1fUL, 0x79b1b1c8UL, 0xb65b5bedUL,
	0xd46a6abeUL, 0x8dcbcb46UL, 0x67bebed9UL, 0x7239394bUL,
	0x944a4adeUL, 0x984c4cd4UL, 0xb05858e8UL, 0x85cfcf4aUL,
	0xbbd0d06bUL, 0xc5efef2aUL, 0x4faaaae5UL, 0xedfbfb16UL,
	0x864343c5UL, 0x9a4d4dd7UL, 0x66333355UL, 0x11858594UL,
	0x8a4545cfUL, 0xe9f9f910UL, 0x04020206UL, 0xfe7f7f81UL,
	0xa05050f0UL, 0x783c3c44UL, 0x259f9fbaUL, 0x4ba8a8e3UL,
	0xa25151f3UL, 0x5da3a3feUL, 0x804040c0UL, 0x058f8f8aUL,
	0x3f9292adUL, 0x219d9dbcUL, 0x70383848UL, 0xf1f5f504UL,
	0x63bcbcdfUL, 0x77b6b6c1UL, 0xafdada75UL, 0x42212163UL,
	0x20101030UL, 0xe5ffff1aUL, 0xfdf3f30eUL, 0xbfd2d26dUL,
	0x81cdcd4cUL, 0x180c0c14UL, 0x26131335UL, 0xc3ecec2fUL,
	0xbe5f5fe1UL, 0x359797a2UL, 0x884444ccUL, 0x2e171739UL,
	0x93c4c457UL, 0x55a7a7f2UL, 0xfc7e7e82UL, 0x7a3d3d47UL,
	0xc86464acUL, 0xba5d5de7UL, 0x3219192bUL, 0xe6737395UL,
	0xc06060a0UL, 0x19818198UL, 0x9e4f4fd1UL, 0xa3dcdc7fUL,
	0x44222266UL, 0x542a2a7eUL, 0x3b9090abUL, 0x0b888883UL,
	0x8c4646caUL, 0xc7eeee29UL, 0x6bb8b8d3UL, 0x2814143cUL,
	0xa7dede79UL, 0xbc5e5ee2UL, 0x160b0b1dUL, 0xaddbdb76UL,
	0xdbe0e03bUL, 0x64323256UL, 0x743a3a4eUL, 0x140a0a1eUL,
	0x924949dbUL, 0x0c06060aUL, 0x4824246cUL, 0xb85c5ce4UL,
	0x9fc2c25dUL, 0xbdd3d36eUL, 0x43acacefUL, 0xc46262a6UL,
	0x399191a8UL, 0x319595a4UL, 0xd3e4e437UL, 0xf279798bUL,
	0xd5e7e732UL, 0x8bc8c843UL, 0x6e373759UL, 0xda6d6db7UL,
	0x018d8d8cUL, 0xb1d5d564UL, 0x9c4e4ed2UL, 0x49a9a9e0UL,
	0xd86c6cb4UL, 0xac5656faUL, 0xf3f4f407UL, 0xcfeaea25UL,
	0xca6565afUL, 0xf47a7a8eUL, 0x47aeaee9UL, 0x10080818UL,
	0x6fbabad5UL, 0xf0787888UL, 0x4a25256fUL, 0x5c2e2e72UL,
	0x381c1c24UL, 0x57a6a6f1UL, 0x73b4b4c7UL, 0x97c6c651UL,
	0xcbe8e823UL, 0xa1dddd7cUL, 0xe874749cUL, 0x3e1f1f21UL,
	0x964b4bddUL, 0x61bdbddcUL, 0x0d8b8b86UL, 0x0f8a8a85UL,
	0xe0707090UL, 0x7c3e3e42UL, 0x71b5b5c4UL, 0xcc6666aaUL,
	0x904848d8UL, 0x06030305UL, 0xf7f6f601UL, 0x1c0e0e12UL,
	0xc26161a3UL, 0x6a35355fUL, 0xae5757f9UL, 0x69b9b9d0UL,
	0x17868691UL, 0x99c1c158UL, 0x3a1d1d27UL, 0x279e9eb9UL,
	0xd9e1e138UL, 0xebf8f813UL, 0x2b9898b3UL, 0x22111133UL,
	0xd26969bbUL, 0xa9d9d970UL, 0x078e8e89UL, 0x339494a7UL,
	0x2d9b9bb6UL, 0x3c1e1e22UL, 0x15878792UL, 0xc9e9e920UL,
	0x87cece49UL, 0xaa5555ffUL, 0x50282878UL, 0xa5dfdf7aUL,
	0x038c8c8fUL, 0x59a1a1f8UL, 0x09898980UL, 0x1a0d0d17UL,
	0x65bfbfdaUL, 0xd7e6e631UL, 0x844242c6UL, 0xd06868b8UL,
	0x824141c3UL, 0x299999b0UL, 0x5a2d2d77UL, 0x1e0f0f11UL,
	0x7bb0b0cbUL, 0xa85454fcUL, 0x6dbbbbd6UL, 0x2c16163aUL,
};

static const uint32_t Te4[256] = {
	0x63636363UL, 0x7c7c7c7cUL, 0x77777777UL, 0x7b7b7b7bUL,
	0xf2f2f2f2UL, 0x6b6b6b6bUL, 0x6f6f6f6fUL, 0xc5c5c5c5UL,
	0x30303030UL, 0x01010101UL, 0x67676767UL, 0x2b2b2b2bUL,
	0xfefefefeUL, 0xd7d7d7d7UL, 0xababababUL, 0x76767676UL,
	0xcacacacaUL, 0x82828282UL, 0xc9c9c9c9UL, 0x7d7d7d7dUL,
	0xfafafafaUL, 0x59595959UL, 0x47474747UL, 0xf0f0f0f0UL,
	0xadadadadUL, 0xd4d4d4d4UL, 0xa2a2a2a2UL, 0xafafafafUL,
	0x9c9c9c9cUL, 0xa4a4a4a4UL, 0x72727272UL, 0xc0c0c0c0UL,
	0xb7b7b7b7UL, 0xfdfdfdfdUL, 0x93939393UL, 0x26262626UL,
	0x36363636UL, 0x3f3f3f3fUL, 0xf7f7f7f7UL, 0xccccccccUL,
	0x34343434UL, 0xa5a5a5a5UL, 0xe5e5e5e5UL, 0xf1f1f1f1UL,
	0x71717171UL, 0xd8d8d8d8UL, 0x31313131UL, 0x15151515UL,
	0x04040404UL, 0xc7c7c7c7UL, 0x23232323UL, 0xc3c3c3c3UL,
	0x18181818UL, 0x96969696UL, 0x05050505UL, 0x9a9a9a9aUL,
	0x07070707UL, 0x12121212UL, 0x80808080UL, 0xe2e2e2e2UL,
	0xebebebebUL, 0x27272727UL, 0xb2b2b2b2UL, 0x75757575UL,
	0x09090909UL, 0x83838383UL, 0x2c2c2c2cUL, 0x1a1a1a1aUL,
	0x1b1b1b1bUL, 0x6e6e6e6eUL, 0x5a5a5a5aUL, 0xa0a0a0a0UL,
	0x52525252UL, 0x3b3b3b3bUL, 0xd6d6d6d6UL, 0xb3b3b3b3UL,
	0x29292929UL, 0xe3e3e3e3UL, 0x2f2f2f2fUL, 0x84848484UL,
	0x53535353UL, 0xd1d1d1d1UL, 0x00000000UL, 0xededededUL,
	0x20202020UL, 0xfcfcfcfcUL, 0xb1b1b1b1UL, 0x5b5b5b5bUL,
	0x6a6a6a6aUL, 0xcbcbcbcbUL, 0xbebebebeUL, 0x39393939UL,
	0x4a4a4a4aUL, 0x4c4c4c4cUL, 0x58585858UL, 0xcfcfcfcfUL,
	0xd0d0d0d0UL, 0xefefefefUL, 0xaaaaaaaaUL, 0xfbfbfbfbUL,
	0x43434343UL, 0x4d4d4d4dUL, 0x33333333UL, 0x85858585UL,
	0x45454545UL, 0xf9f9f9f9UL, 0x02020202UL, 0x7f7f7f7fUL,
	0x50505050UL, 0x3c3c3c3cUL, 0x9f9f9f9fUL, 0xa8a8a8a8UL,
	0x51515151UL, 0xa3a3a3a3UL, 0x40404040UL, 0x8f8f8f8fUL,
	0x92929292UL, 0x9d9d9d9dUL, 0x38383838UL, 0xf5f5f5f5UL,
	0xbcbcbcbcUL, 0xb6b6b6b6UL, 0xdadadadaUL, 0x21212121UL,
	0x10101010UL, 0xffffffffUL, 0xf3f3f3f3UL, 0xd2d2d2d2UL,
	0xcdcdcdcdUL, 0x0c0c0c0cUL, 0x13131313UL, 0xececececUL,
	0x5f5f5f5fUL, 0x97979797UL, 0x44444444UL, 0x17171717UL,
	0xc4c4c4c4UL, 0xa7a7a7a7UL, 0x7e7e7e7eUL, 0x3d3d3d3dUL,
	0x64646464UL, 0x5d5d5d5dUL, 0x19191919UL, 0x73737373UL,
	0x60606060UL, 0x81818181UL, 0x4f4f4f4fUL, 0xdcdcdcdcUL,
	0x22222222UL, 0x2a2a2a2aUL, 0x90909090UL, 0x88888888UL,
	0x46464646UL, 0xeeeeeeeeUL, 0xb8b8b8b8UL, 0x14141414UL,
	0xdedededeUL, 0x5e5e5e5eUL, 0x0b0b0b0bUL, 0xdbdbdbdbUL,
	0xe0e0e0e0UL, 0x32323232UL, 0x3a3a3a3aUL, 0x0a0a0a0aUL,
	0x49494949UL, 0x06060606UL, 0x24242424UL, 0x5c5c5c5cUL,
	0xc2c2c2c2UL, 0xd3d3d3d3UL, 0xacacacacUL, 0x62626262UL,
	0x91919191UL, 0x95959595UL, 0xe4e4e4e4UL, 0x79797979UL,
	0xe7e7e7e7UL, 0xc8c8c8c8UL, 0x37373737UL, 0x6d6d6d6dUL,
	0x8d8d8d8dUL, 0xd5d5d5d5UL, 0x4e4e4e4eUL, 0xa9a9a9a9UL,
	0x6c6c6c6cUL, 0x56565656UL, 0xf4f4f4f4UL, 0xeaeaeaeaUL,
	0x65656565UL, 0x7a7a7a7aUL, 0xaeaeaeaeUL, 0x08080808UL,
	0xbabababaUL, 0x78787878UL, 0x25252525UL, 0x2e2e2e2eUL,
	0x1c1c1c1cUL, 0xa6a6a6a6UL, 0xb4b4b4b4UL, 0xc6c6c6c6UL,
	0xe8e8e8e8UL, 0xddddddddUL, 0x74747474UL, 0x1f1f1f1fUL,
	0x4b4b4b4bUL, 0xbdbdbdbdUL, 0x8b8b8b8bUL, 0x8a8a8a8aUL,
	0x70707070UL, 0x3e3e3e3eUL, 0xb5b5b5b5UL, 0x66666666UL,
	0x48484848UL, 0x03030303UL, 0xf6f6f6f6UL, 0x0e0e0e0eUL,
	0x61616161UL, 0x35353535UL, 0x57575757UL, 0xb9b9b9b9UL,
	0x86868686UL, 0xc1c1c1c1UL, 0x1d1d1d1dUL, 0x9e9e9e9eUL,
	0xe1e1e1e1UL, 0xf8f8f8f8UL, 0x98989898UL, 0x11111111UL,
	0x69696969UL, 0xd9d9d9d9UL, 0x8e8e8e8eUL, 0x94949494UL,
	0x9b9b9b9bUL, 0x1e1e1e1eUL, 0x87878787UL, 0xe9e9e9e9UL,
	0xcecececeUL, 0x55555555UL, 0x28282828UL, 0xdfdfdfdfUL,
	0x8c8c8c8cUL, 0xa1a1a1a1UL, 0x89898989UL, 0x0d0d0d0dUL,
	0xbfbfbfbfUL, 0xe6e6e6e6UL, 0x42424242UL, 0x68686868UL,
	0x41414141UL, 0x99999999UL, 0x2d2d2d2dUL, 0x0f0f0f0fUL,
	0xb0b0b0b0UL, 0x54545454UL, 0xbbbbbbbbUL, 0x16161616UL,
};

static const uint32_t rcon[] = {
    0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL,
    0x10000000UL, 0x20000000UL, 0x40000000UL, 0x80000000UL,
    0x1B000000UL, 0x36000000UL
};

#define aes(plain, key, cipher) aes_rounds((plain), (key), 10, (cipher))


void aes_rounds(const uint8_t *plain, const uint8_t *key, const uint8_t rounds, uint8_t *cipher) {
	uint8_t i;
	uint8_t r = rounds;
	uint32_t k0, k1, k2, k3;
	uint32_t s0, s1, s2, s3;
	uint32_t t0, t1, t2, t3;

	LOAD32B(key,      &k0);
	LOAD32B(key + 4,  &k1);
	LOAD32B(key + 8,  &k2);
	LOAD32B(key + 12, &k3);

	LOAD32B(plain,  	 &s0);
	LOAD32B(plain  +  4, &s1);
	LOAD32B(plain  +  8, &s2);
	LOAD32B(plain  + 12, &s3);

	s0 ^= k0;
	s1 ^= k1;
	s2 ^= k2;
	s3 ^= k3;

	if (10 != rounds) // for reduced-round AES
		r++;

	for (i = 0; i < r - 1 ; i++) {
		k0 ^= (rcon[i] ^
			Te4_3[byte(k3, 2)] ^
			Te4_2[byte(k3, 1)] ^
			Te4_1[byte(k3, 0)] ^
			Te4_0[byte(k3, 3)]);
		k1 ^= k0;
		k2 ^= k1;
		k3 ^= k2;

		t0 = Te0(byte(s0, 3)) ^
			 Te1(byte(s1, 2)) ^
			 Te2(byte(s2, 1)) ^
			 Te3(byte(s3, 0)) ^
			 k0;
		t1 = Te0(byte(s1, 3)) ^
			 Te1(byte(s2, 2)) ^
			 Te2(byte(s3, 1)) ^
			 Te3(byte(s0, 0)) ^
			 k1;
		t2 = Te0(byte(s2, 3)) ^
			 Te1(byte(s3, 2)) ^
			 Te2(byte(s0, 1)) ^
			 Te3(byte(s1, 0)) ^
			 k2;
		t3 = Te0(byte(s3, 3)) ^
			 Te1(byte(s0, 2)) ^
			 Te2(byte(s1, 1)) ^
			 Te3(byte(s2, 0)) ^
			 k3;

		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}

	if (10 == rounds) {  // the last round for the full AES
		k0 ^= rcon[i] ^
			Te4_3[byte(k3, 2)] ^
			Te4_2[byte(k3, 1)] ^
			Te4_1[byte(k3, 0)] ^
			Te4_0[byte(k3, 3)];
		k1 ^= k0;
		k2 ^= k1;
		k3 ^= k2;

		s0 = Te4_3[byte(t0, 3)] ^
			Te4_2[byte(t1, 2)] ^
			Te4_1[byte(t2, 1)] ^
			Te4_0[byte(t3, 0)] ^
			k0;
		s1 = Te4_3[byte(t1, 3)] ^
			Te4_2[byte(t2, 2)] ^
			Te4_1[byte(t3, 1)] ^
			Te4_0[byte(t0, 0)] ^
			k1;
		s2 = Te4_3[byte(t2, 3)] ^
			Te4_2[byte(t3, 2)] ^
			Te4_1[byte(t0, 1)] ^
			Te4_0[byte(t1, 0)] ^
			k2;
		s3 = Te4_3[byte(t3, 3)] ^
			Te4_2[byte(t0, 2)] ^
			Te4_1[byte(t1, 1)] ^
			Te4_0[byte(t2, 0)] ^
			k3;
	}

	STORE32B(s0, cipher);
	STORE32B(s1, cipher + 4);
	STORE32B(s2, cipher + 8);
	STORE32B(s3, cipher + 12);
}

#endif  /* __AES_H__ */
