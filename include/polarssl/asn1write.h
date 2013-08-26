/**
 * \file asn1write.h
 *
 * \brief ASN.1 buffer writing functionality
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_ASN1_WRITE_H
#define POLARSSL_ASN1_WRITE_H

#include "asn1.h"

#define ASN1_CHK_ADD(g, f) if( ( ret = f ) < 0 ) return( ret ); else g += ret

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Write a length field in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param len       the length to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_len( unsigned char **p, unsigned char *start, size_t len );

/**
 * \brief           Write a ASN.1 tag in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param tag       the tag to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_tag( unsigned char **p, unsigned char *start, unsigned char tag );

#if defined(POLARSSL_BIGNUM_C)
/**
 * \brief           Write a big number (ASN1_INTEGER) in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param X         the MPI to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_mpi( unsigned char **p, unsigned char *start, mpi *X );
#endif

/**
 * \brief           Write a NULL tag (ASN1_NULL) with zero data in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 *
 * \return          the length written or a negative error code
 */
int asn1_write_null( unsigned char **p, unsigned char *start );

/**
 * \brief           Write an OID tag (ASN1_OID) and data in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param oid       the OID to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_oid( unsigned char **p, unsigned char *start, const char *oid );

/**
 * \brief           Write an AlgorithmIdentifier sequence in ASN.1 format
 *                  Note: function works backwards in data buffer
 *                  Note: Uses NULL as algorithm parameter
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param oid       the OID of the algorithm
 *
 * \return          the length written or a negative error code
 */
int asn1_write_algorithm_identifier( unsigned char **p, unsigned char *start,
                                     const char *oid );

/**
 * \brief           Write an int tag (ASN1_INTEGER) and value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param val       the integer value
 *
 * \return          the length written or a negative error code
 */
int asn1_write_int( unsigned char **p, unsigned char *start, int val );

/**
 * \brief           Write a printable string tag (ASN1_PRINTABLE_STRING) and
 *                  value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param text      the text to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_printable_string( unsigned char **p, unsigned char *start,
                                 char *text );

/**
 * \brief           Write an IA5 string tag (ASN1_IA5_STRING) and
 *                  value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param text      the text to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_ia5_string( unsigned char **p, unsigned char *start,
                                 char *text );

/**
 * \brief           Write a bitstring tag (ASN1_BIT_STRING) and
 *                  value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param buf       the bitstring
 * \param bits      the total number of bits in the bitstring
 *
 * \return          the length written or a negative error code
 */
int asn1_write_bitstring( unsigned char **p, unsigned char *start,
                          const unsigned char *buf, size_t bits );

/**
 * \brief           Write an octet string tag (ASN1_OCTET_STRING) and
 *                  value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param buf       data buffer to write
 * \param size      length of the data buffer
 *
 * \return          the length written or a negative error code
 */
int asn1_write_octet_string( unsigned char **p, unsigned char *start,
                             const unsigned char *buf, size_t size );

/**
 * \brief           Write raw buffer data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param buf       data buffer to write
 * \param size      length of the data buffer
 *
 * \return          the length written or a negative error code
 */
int asn1_write_raw_buffer( unsigned char **p, unsigned char *start,
                           const unsigned char *buf, size_t size );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_ASN1_WRITE_H */
