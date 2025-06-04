#include "ndpi_typedefs.h"
#include "ndpi_api.h"

/*
 * Validate and skip GRE headers, returning the offset
 * of the payload inside the packet buffer. Returns 0
 * if the packet is not a valid GRE tunnel or is too short.
 */
uint32_t ndpi_is_valid_gre_tunnel(const void *header,
                                  const uint8_t *packet,
                                  uint16_t ip_offset,
                                  uint16_t ip_len)
{
  struct ndpi_pcap_pkthdr_compat {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
  };

  const struct ndpi_pcap_pkthdr_compat *hdr =
    (const struct ndpi_pcap_pkthdr_compat *)header;

  if(hdr->caplen < ip_offset + ip_len + sizeof(struct ndpi_gre_basehdr))
    return 0; /* Too short for GRE header */

  uint32_t offset = ip_offset + ip_len;
  const struct ndpi_gre_basehdr *grehdr = (const struct ndpi_gre_basehdr*)&packet[offset];
  offset += sizeof(struct ndpi_gre_basehdr);

  if(NDPI_GRE_IS_FLAGS(grehdr->flags))
    return 0;
  if(NDPI_GRE_IS_REC(grehdr->flags))
    return 0;

  if(NDPI_GRE_IS_VERSION_0(grehdr->flags)) {
    if(NDPI_GRE_IS_CSUM(grehdr->flags)) {
      if(hdr->caplen < offset + 4)
        return 0;
      offset += 4;
    }
    if(NDPI_GRE_IS_KEY(grehdr->flags)) {
      if(hdr->caplen < offset + 4)
        return 0;
      offset += 4;
    }
    if(NDPI_GRE_IS_SEQ(grehdr->flags)) {
      if(hdr->caplen < offset + 4)
        return 0;
      offset += 4;
    }
  } else if(NDPI_GRE_IS_VERSION_1(grehdr->flags)) {
    if(NDPI_GRE_IS_CSUM(grehdr->flags))
      return 0;
    if(NDPI_GRE_IS_ROUTING(grehdr->flags))
      return 0;
    if(!NDPI_GRE_IS_KEY(grehdr->flags))
      return 0;
    if(NDPI_GRE_IS_STRICT(grehdr->flags))
      return 0;
    if(grehdr->protocol != NDPI_GRE_PROTO_PPP)
      return 0;
    if(hdr->caplen < offset + 4)
      return 0;
    offset += 4;
    if(NDPI_GRE_IS_SEQ(grehdr->flags)) {
      if(hdr->caplen < offset + 4)
        return 0;
      offset += 4;
    }
    if(NDPI_GRE_IS_ACK(grehdr->flags)) {
      if(hdr->caplen < offset + 4)
        return 0;
      offset += 4;
    }
  } else {
    return 0; /* Unsupported GRE version */
  }

  if(grehdr->protocol == NDPI_GRE_PROTO_ERSPAN_I_II ||
     grehdr->protocol == NDPI_GRE_PROTO_ERSPAN_III) {
    if(hdr->caplen < offset + NDPI_ERSPAN_HDRLEN)
      return 0;
    offset += NDPI_ERSPAN_HDRLEN;
  } else if(grehdr->protocol == NDPI_GRE_PROTO_LCC_SLL) {
    if(hdr->caplen < offset + NDPI_LCC_SLL_HDRLEN)
      return 0;
    offset += NDPI_LCC_SLL_HDRLEN;
  } else if(grehdr->protocol == NDPI_GRE_PROTO_PPP) {
    if(hdr->caplen < offset + NDPI_PPP_HDRLEN)
      return 0;
    offset += NDPI_PPP_HDRLEN;
  }

  return offset;
}
