/*
 * websocket.c
 *
 * Copyright (C) 2018 by Leonn Paiva <leonn.paiva@gmail.com>
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WEBSOCKET

#include "ndpi_api.h"

enum websocket_opcode
{
    CONTINUATION_FRAME = 0x00,
    TEXT_FRAME = 0x01,
    BINARY_FRAME = 0x02,
    CONNECTION_CLOSE_FRAME = 0x08,
    PING_FRAME = 0x09,
    PONG_FRAME = 0x10,
    UNKNOWN_FRAME = 0xFF
};

PACK_ON
struct websocket_header
{
    uint8_t fin : 1;
    uint8_t opcode : 4;
    uint8_t masked : 1;
    uint8_t payload_length : 7;
} PACK_OFF;

static void set_websocket_detected(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    /* If no custom protocol has been detected */
    if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
    {
        ndpi_search_tcp_or_udp(ndpi_struct, flow);

        ndpi_int_reset_protocol(flow);
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WEBSOCKET, flow->guessed_host_protocol_id);
    }
}

/*************************************************************************************************/

static void ndpi_check_websocket(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct websocket_header websocket_hdr;
    struct ndpi_packet_struct *packet = &flow->packet;

    if (packet->payload_packet_len < sizeof(u_int16_t))
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    websocket_hdr.fin = packet->payload[0] & 0x80 != 0 ? 1 : 0;
    websocket_hdr.opcode = packet->payload[0] & 0x0F;
    websocket_hdr.masked = packet->payload[1] & 0x80 != 0 ? 1 : 0;
    websocket_hdr.payload_length = packet->payload[1] & 0x7F;

    switch (websocket_hdr.opcode)
    {
        case CONTINUATION_FRAME:
        case TEXT_FRAME:
        case BINARY_FRAME:
        case CONNECTION_CLOSE_FRAME:
        case PING_FRAME:
        case PONG_FRAME:
            set_websocket_detected(ndpi_struct, flow);
            break;
        default:
            NDPI_LOG_DBG(ndpi_struct, "Invalid WEBSOCKET type");
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            break;
    }

    if (websocket_hdr.masked == 1  && packet->payload_packet_len < sizeof(u_int32_t)) {
        NDPI_LOG_DBG(ndpi_struct, "Invalid WEBSOCKET payload");
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
}

void ndpi_search_websocket(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;

    // Break after 6 packets.
    if (flow->packet_counter > 10)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    {
        return;
    }

    NDPI_LOG_DBG(ndpi_struct, "search WEBSOCKET\n");
    ndpi_check_websocket(ndpi_struct, flow);

    return;
}

/* ********************************* */

void init_websocket_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
                              NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection("WEBSOCKET", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_WEBSOCKET,
                                        ndpi_search_websocket, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

    *id += 1;
}
