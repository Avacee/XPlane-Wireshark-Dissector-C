/* packet-xplane.c
 * Routines for X-Plane packet dissection
 * Copyright 2020, Avacee
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GNU v3
 */

 /*
  * A dissector for UDP packets for Laminar Research's X-Plane Flight Simulator
  */

#include <config.h>

#if 0
  /* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/prefs.h>
#include <epan/unit_strings.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_xplane(void);
void proto_register_xplane(void);

/* Initialize the protocol and registered fields */
static int proto_xplane = -1;

static gint ett_xplane_acfn = -1;
static gint ett_xplane_acpr = -1;
static gint ett_xplane_alrt = -1;
static gint ett_xplane_becn = -1;
static gint ett_xplane_cmnd = -1;
static gint ett_xplane_data = -1;
static gint ett_xplane_dcoc = -1;
static gint ett_xplane_dref = -1;
static gint ett_xplane_dsel = -1;
static gint ett_xplane_fail = -1;
static gint ett_xplane_flir_in = -1;
static gint ett_xplane_flir_out = -1;
static gint ett_xplane_ise4 = -1;
static gint ett_xplane_ise6 = -1;
static gint ett_xplane_lsnd = -1;
static gint ett_xplane_nfal = -1;
static gint ett_xplane_nrec = -1;
static gint ett_xplane_objl = -1;
static gint ett_xplane_objn = -1;
static gint ett_xplane_prel = -1;
static gint ett_xplane_quit = -1;
static gint ett_xplane_radr_in = -1;
static gint ett_xplane_radr_out = -1;
static gint ett_xplane_reco = -1;
static gint ett_xplane_rese = -1;
static gint ett_xplane_rpos_in = -1;
static gint ett_xplane_rpos_out = -1;
static gint ett_xplane_rref_in = -1;
static gint ett_xplane_rref_out = -1;
static gint ett_xplane_shut = -1;
static gint ett_xplane_simo = -1;
static gint ett_xplane_soun = -1;
static gint ett_xplane_ssnd = -1;
static gint ett_xplane_ucoc = -1;
static gint ett_xplane_usel = -1;
static gint ett_xplane_vehx = -1;

static int hf_xplane_acfn_header = -1;
static int hf_xplane_acfn_index = -1;
static int hf_xplane_acfn_path = -1;
static int hf_xplane_acfn_padding = -1;
static int hf_xplane_acfn_livery = -1;

static int hf_xplane_acpr_header = -1;
static int hf_xplane_acpr_index = -1;
static int hf_xplane_acpr_path = -1;
static int hf_xplane_acpr_livery = -1;
static int hf_xplane_acpr_padding = -1;
static int hf_xplane_acpr_starttype = -1;
static int hf_xplane_acpr_aircraftindex = -1;
static int hf_xplane_acpr_ICAO = -1;
static int hf_xplane_acpr_runwayindex = -1;
static int hf_xplane_acpr_runwaydirection = -1;
static int hf_xplane_acpr_latitude = -1;
static int hf_xplane_acpr_longitude = -1;
static int hf_xplane_acpr_elevation = -1;
static int hf_xplane_acpr_trueheading = -1;
static int hf_xplane_acpr_speed = -1;

static int hf_xplane_alrt_header = -1;
static int hf_xplane_alrt_line1 = -1;
static int hf_xplane_alrt_line2 = -1;
static int hf_xplane_alrt_line3 = -1;
static int hf_xplane_alrt_line4 = -1;

static int hf_xplane_becn_header = -1;
static int hf_xplane_becn_major = -1;
static int hf_xplane_becn_minor = -1;
static int hf_xplane_becn_hostid = -1;
static int hf_xplane_becn_version = -1;
static int hf_xplane_becn_role = -1;
static int hf_xplane_becn_port = -1;
static int hf_xplane_becn_name = -1;
static int hf_xplane_becn_newport = -1;

static int hf_xplane_cmnd_header = -1;
static int hf_xplane_cmnd_command = -1;

static int hf_xplane_data_header = -1;
static int hf_xplane_data_index = -1;
static int hf_xplane_data_a = -1;
static int hf_xplane_data_b = -1;
static int hf_xplane_data_c = -1;
static int hf_xplane_data_d = -1;
static int hf_xplane_data_e = -1;
static int hf_xplane_data_f = -1;
static int hf_xplane_data_g = -1;
static int hf_xplane_data_h = -1;

static int hf_xplane_dcoc_header = -1;
static int hf_xplane_dcoc_id = -1;

static int hf_xplane_dref_header = -1;
static int hf_xplane_dref_value = -1;
static int hf_xplane_dref_dataref = -1;

static int hf_xplane_dsel_header = -1;
static int hf_xplane_dsel_id = -1;

static int hf_xplane_fail_header = -1;
static int hf_xplane_fail_id = -1;

static int hf_xplane_flir_in_header = -1;
static int hf_xplane_flir_in_framerate = -1;

static int hf_xplane_flir_out_header = -1;
static int hf_xplane_flir_out_height = -1;
static int hf_xplane_flir_out_width = -1;
static int hf_xplane_flir_out_frameindex = -1;
static int hf_xplane_flir_out_framecount = -1;
static int hf_xplane_flir_out_imagedata = -1;

static int hf_xplane_ise4_header = -1;
static int hf_xplane_ise4_machinetype = -1;
static int hf_xplane_ise4_address = -1;
static int hf_xplane_ise4_port = -1;
static int hf_xplane_ise4_enabled = -1;

static int hf_xplane_ise6_header = -1;
static int hf_xplane_ise6_machinetype = -1;
static int hf_xplane_ise6_address = -1;
static int hf_xplane_ise6_port = -1;
static int hf_xplane_ise6_enabled = -1;

static int hf_xplane_lsnd_header = -1;
static int hf_xplane_lsnd_index = -1;
static int hf_xplane_lsnd_speed = -1;
static int hf_xplane_lsnd_volume = -1;
static int hf_xplane_lsnd_filename = -1;

static int hf_xplane_nfal_header = -1;
static int hf_xplane_nfal_navaidcode = -1;

static int hf_xplane_nrec_header = -1;
static int hf_xplane_nrec_navaidcode = -1;

static int hf_xplane_objl_header = -1;
static int hf_xplane_objl_index = -1;
static int hf_xplane_objl_padding1 = -1;
static int hf_xplane_objl_latitude = -1;
static int hf_xplane_objl_longitude = -1;
static int hf_xplane_objl_elevation = -1;
static int hf_xplane_objl_psi = -1;
static int hf_xplane_objl_theta = -1;
static int hf_xplane_objl_phi = -1;
static int hf_xplane_objl_onground = -1;
static int hf_xplane_objl_smokesize = -1;
static int hf_xplane_objl_padding2 = -1;

static int hf_xplane_objn_header = -1;
static int hf_xplane_objn_index = -1;
static int hf_xplane_objn_filename = -1;

static int hf_xplane_prel_header = -1;
static int hf_xplane_prel_starttype = -1;
static int hf_xplane_prel_aircraftindex = -1;
static int hf_xplane_prel_ICAO = -1;
static int hf_xplane_prel_runwayindex = -1;
static int hf_xplane_prel_runwaydirection = -1;
static int hf_xplane_prel_latitude = -1;
static int hf_xplane_prel_longitude = -1;
static int hf_xplane_prel_elevation = -1;
static int hf_xplane_prel_trueheading = -1;
static int hf_xplane_prel_speed = -1;

static int hf_xplane_quit_header = -1;

static int hf_xplane_radr_in_header = -1;
static int hf_xplane_radr_in_pointcount = -1;

static int hf_xplane_radr_out_header = -1;
static int hf_xplane_radr_out_longitude = -1;
static int hf_xplane_radr_out_latitude = -1;
static int hf_xplane_radr_out_precipitation = -1;
static int hf_xplane_radr_out_height = -1;

static int hf_xplane_reco_header = -1;
static int hf_xplane_reco_id = -1;

static int hf_xplane_rese_header = -1;

static int hf_xplane_rpos_in_header = -1;
static int hf_xplane_rpos_in_frequency = -1;

static int hf_xplane_rpos_out_header = -1;
static int hf_xplane_rpos_out_longitude = -1;
static int hf_xplane_rpos_out_latitude = -1;
static int hf_xplane_rpos_out_elevation = -1;
static int hf_xplane_rpos_out_height = -1;
static int hf_xplane_rpos_out_theta = -1;
static int hf_xplane_rpos_out_psi = -1;
static int hf_xplane_rpos_out_phi = -1;
static int hf_xplane_rpos_out_vx = -1;
static int hf_xplane_rpos_out_vy = -1;
static int hf_xplane_rpos_out_vz = -1;
static int hf_xplane_rpos_out_rollrate = -1;
static int hf_xplane_rpos_out_pitchrate = -1;
static int hf_xplane_rpos_out_yawrate = -1;

static int hf_xplane_rref_in_header = -1;
static int hf_xplane_rref_in_frequency = -1;
static int hf_xplane_rref_in_id = -1;
static int hf_xplane_rref_in_dataref = -1;

static int hf_xplane_rref_out_header = -1;
static int hf_xplane_rref_out_id = -1;
static int hf_xplane_rref_out_value = -1;

static int hf_xplane_shut_header = -1;

static int hf_xplane_simo_header = -1;
static int hf_xplane_simo_action = -1;
static int hf_xplane_simo_filename = -1;

static int hf_xplane_soun_header = -1;
static int hf_xplane_soun_speed = -1;
static int hf_xplane_soun_volume = -1;
static int hf_xplane_soun_filename = -1;

static int hf_xplane_ssnd_header = -1;
static int hf_xplane_ssnd_index = -1;
static int hf_xplane_ssnd_speed = -1;
static int hf_xplane_ssnd_volume = -1;
static int hf_xplane_ssnd_filename = -1;

static int hf_xplane_ucoc_header = -1;
static int hf_xplane_ucoc_id = -1;

static int hf_xplane_usel_header = -1;
static int hf_xplane_usel_id = -1;

static int hf_xplane_vehx_header = -1;
static int hf_xplane_vehx_id = -1;
static int hf_xplane_vehx_latitude = -1;
static int hf_xplane_vehx_longitude = -1;
static int hf_xplane_vehx_elevation = -1;
static int hf_xplane_vehx_heading = -1;
static int hf_xplane_vehx_pitch = -1;
static int hf_xplane_vehx_roll = -1;

#define xplane_MIN_PACKET_LENGTH 5
#define xplane_ACFN_PACKET_LENGTH 165
#define xplane_ACPR_PACKET_LENGTH 229
#define xplane_ALRT_PACKET_LENGTH 965
#define xplane_DATA_STRUCT_LENGTH 36
#define xplane_DATA_INDEX_LENGTH 4
#define xplane_DREF_PACKET_LENGTH 509
#define xplane_ISE4_PACKET_LENGTH 37
#define xplane_ISE6_PACKET_LENGTH 85
#define xplane_LSND_PACKET_LENGTH 517
#define xplane_OBJL_PACKET_LENGTH 61
#define xplane_OBJN_PACKET_LENGTH 509
#define xplane_PREL_PACKET_LENGTH 69
#define xplane_QUIT_PACKET_LENGTH xplane_MIN_PACKET_LENGTH
#define xplane_RADR_STRUCT_LENGTH 13
#define xplane_RESE_PACKET_LENGTH xplane_MIN_PACKET_LENGTH
#define xplane_RPOS_OUT_PACKET_LENGTH 69
#define xplane_RREF_IN_PACKET_LENGTH 413
#define xplane_SHUT_PACKET_LENGTH xplane_MIN_PACKET_LENGTH
#define xplane_SOUN_PACKET_LENGTH 513
#define xplane_SSND_PACKET_LENGTH 517
#define xplane_VEHX_PACKET_LENGTH 45

#define xplane_HEADER_LENGTH 5

#define xplane_UDP_PORT 49005
#define xplane_BECN_PORT 49707
static guint xplane_pref_udp_port = xplane_UDP_PORT;
static guint xplane_pref_becn_port = xplane_BECN_PORT;

static const value_string vals_Becn_HostID[] = {
    { 1, "X-Plane" },
    { 2, "Plane Maker" },
    { 0, NULL }
};

static const value_string vals_MachineRole[] = {
    { 1, "Master" },
    { 2, "External Visual" },
    { 3, "IOS" },
    { 0, NULL }
};

static const value_string vals_StartType[] = {
    { 5  , "RepeatLast" },
    { 6  , "LatLong" },
    { 7  , "GeneralArea" },
    { 8  , "NearestAirport" },
    { 9  , "SnapshotLoad" },
    { 10 , "Ramp" },
    { 11 , "Runway" },
    { 12 , "RunwayVFR" },
    { 13 , "RunwayIFR" },
    { 14 , "GrassStrip" },
    { 15 , "DirtStrip" },
    { 16 , "GravelStrip" },
    { 17 , "WaterRunway" },
    { 18 , "Helipad" },
    { 19 , "CarrierCatapult" },
    { 20 , "GliderTowPlane" },
    { 21 , "GliderWinch" },
    { 22 , "FormationFlying" },
    { 23 , "RefuelBoom" },
    { 24 , "RefuelBasket" },
    { 25 , "B52Drop" },
    { 26 , "ShuttlePiggyBack" },
    { 27 , "CarrierApproach" },
    { 28 , "FrigateApproach" },
    { 29 , "SmallOilRigApproach" },
    { 30 , "LargeOilPlatformApproach" },
    { 31 , "ForestFireApproach" },
    { 32 , "Shuttle01" },
    { 33 , "Shuttle02" },
    { 34 , "Shuttle03" },
    { 35 , "Shuttle04" },
    { 36 , "ShuttleGlide" },
    {  0 , NULL }
};

static const value_string vals_ISEx_MachineType[] = {
  { 0, "Multiplayer1" },
  { 1, "Multiplayer2" },
  { 2, "Multiplayer3" },
  { 3, "Multiplayer4" },
  { 4, "Multiplayer5" },
  { 5, "Multiplayer6" },
  { 6, "Multiplayer7" },
  { 7, "Multiplayer8" },
  { 8, "Multiplayer9" },
  { 9, "Multiplayer10" },
  { 10, "Multiplayer11" },
  { 11, "Multiplayer12" },
  { 12, "Multiplayer13" },
  { 13, "Multiplayer14" },
  { 14, "Multiplayer15" },
  { 15, "Multiplayer16" },
  { 16, "Multiplayer17" },
  { 17, "Multiplayer18" },
  { 18, "Multiplayer19" },
  { 19, "ExternalVisual0" },
  { 20, "ExternalVisual1" },
  { 21, "ExternalVisual2" },
  { 22, "ExternalVisual3" },
  { 23, "ExternalVisual4" },
  { 24, "ExternalVisual5" },
  { 25, "ExternalVisual6" },
  { 26, "ExternalVisual7" },
  { 27, "ExternalVisual8" },
  { 28, "ExternalVisual9" },
  { 29, "ExternalVisual10" },
  { 30, "ExternalVisual11" },
  { 31, "ExternalVisual12" },
  { 32, "ExternalVisual13" },
  { 33, "ExternalVisual14" },
  { 34, "ExternalVisual15" },
  { 35, "ExternalVisual16" },
  { 36, "ExternalVisual17" },
  { 37, "ExternalVisual18" },
  { 38, "ExternalVisual19" },
  { 39, "ExternalVisualMaster8" },
  { 42, "IOSMasterThisIsIOS" },
  { 62, "IOSThisIsMaster" },
  { 64, "DataOutputTarget" },
  { 71, "Xavi1" },
  { 72, "Xavi2" },
  { 73, "Xavi3" },
  { 74, "Xavi4" },
  { 75, "ForeFlight" },
  { 76, "ForeFlightBroadcast" },
  { 77, "ControlPadForIOS" },
  {  0, NULL }
};

static int dissect_xplane_acfn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* path = NULL;
    gint32 id;

    proto_item* xplane_acfn_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_acfn_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    proto_tree* xplane_acfn_tree = proto_item_add_subtree(xplane_acfn_item, ett_xplane_acfn);
    proto_item* header_item = proto_tree_add_item(xplane_acfn_tree, hf_xplane_acfn_header, tvb, 0, 4, ENC_ASCII);
    proto_item_append_text(header_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_acfn_tree, hf_xplane_acfn_index, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &id);
    proto_tree_add_item_ret_string(xplane_acfn_tree, hf_xplane_acfn_path, tvb_content, 4, 150, ENC_ASCII, wmem_packet_scope(), &path);
    proto_tree_add_item(xplane_acfn_tree, hf_xplane_acfn_padding, tvb_content, 154, 2, ENC_ASCII);
    proto_tree_add_item(xplane_acfn_tree, hf_xplane_acfn_livery, tvb_content, 156, 4, ENC_LITTLE_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%d Path=%s", id, path);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_acpr(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* path = NULL;
    gint32 id;

    proto_item* xplane_acpr_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_acpr_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    proto_tree* xplane_acpr_tree = proto_item_add_subtree(xplane_acpr_item, ett_xplane_acpr);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_acpr_tree, hf_xplane_acpr_index, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &id);
    proto_tree_add_item_ret_string(xplane_acpr_tree, hf_xplane_acpr_path, tvb_content, 4, 150, ENC_ASCII, wmem_packet_scope(), &path);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_padding, tvb_content, 154, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_livery, tvb_content, 156, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_starttype, tvb_content, 160, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_aircraftindex, tvb_content, 164, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_ICAO, tvb_content, 168, 8, ENC_ASCII);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_runwayindex, tvb_content, 176, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_runwaydirection, tvb_content, 180, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_latitude, tvb_content, 184, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_longitude, tvb_content, 192, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_elevation, tvb_content, 200, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_trueheading, tvb_content, 208, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_acpr_tree, hf_xplane_acpr_speed, tvb_content, 216, 8, ENC_LITTLE_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%d Path=%s", id, path);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_alrt(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_alrt_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_alrt_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    proto_tree* xplane_alrt_tree = proto_item_add_subtree(xplane_alrt_item, ett_xplane_alrt);
    proto_tree_add_item(xplane_alrt_tree, hf_xplane_alrt_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_alrt_tree, hf_xplane_alrt_line1, tvb_content, 0,  240, ENC_ASCII);
    proto_tree_add_item(xplane_alrt_tree, hf_xplane_alrt_line2, tvb_content, 240, 240, ENC_ASCII);
    proto_tree_add_item(xplane_alrt_tree, hf_xplane_alrt_line3, tvb_content, 480, 240, ENC_ASCII);
    proto_tree_add_item(xplane_alrt_tree, hf_xplane_alrt_line4, tvb_content, 720, 240, ENC_ASCII);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_becn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* becn_name = NULL;
    guint32 major, minor;
    gint length;

    proto_item* xplane_becn_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_becn_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    proto_tree* xplane_becn_tree = proto_item_add_subtree(xplane_becn_item, ett_xplane_becn);
    proto_tree_add_item(xplane_becn_tree, hf_xplane_becn_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_uint(xplane_becn_tree, hf_xplane_becn_major, tvb_content, 0, 1, ENC_LITTLE_ENDIAN, &major);
    proto_tree_add_item_ret_uint(xplane_becn_tree, hf_xplane_becn_minor, tvb_content, 1, 1, ENC_LITTLE_ENDIAN, &minor);
    proto_tree_add_item(xplane_becn_tree, hf_xplane_becn_hostid, tvb_content, 2, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_becn_tree, hf_xplane_becn_version, tvb_content, 6, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_becn_tree, hf_xplane_becn_role, tvb_content, 10, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_becn_tree, hf_xplane_becn_port, tvb_content, 14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_string_and_length(xplane_becn_tree, hf_xplane_becn_name, tvb_content, 16, -1, ENC_ASCII, wmem_packet_scope(), &becn_name, &length);
    if (major == 1 && minor == 2)
    {
        proto_tree_add_item(xplane_becn_tree, hf_xplane_becn_newport, tvb_content, 16 + length, 2, ENC_LITTLE_ENDIAN);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Server=%s", becn_name);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_cmnd(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* cmnd_name = NULL;

    proto_item* xplane_cmnd_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_cmnd_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    proto_tree* xplane_cmnd_tree = proto_item_add_subtree(xplane_cmnd_item, ett_xplane_cmnd);
    proto_tree_add_item(xplane_cmnd_tree, hf_xplane_cmnd_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_cmnd_tree, hf_xplane_alrt_line1, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &cmnd_name);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Cmnd=%s", cmnd_name);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    guint recordCount = tvb_captured_length(tvb_content) / xplane_DATA_STRUCT_LENGTH;

    proto_item* xplane_data_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_data_item, " Length=%u, Count=%u", tvb_captured_length(tvb), recordCount);;

    proto_tree* xplane_data_tree = proto_item_add_subtree(xplane_data_item, ett_xplane_data);
    proto_tree_add_item(xplane_data_tree, hf_xplane_data_header, tvb, 0, 4, ENC_ASCII);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Count=%u", recordCount);

    for (guint32 i = 0; i < recordCount; i++)
    {
        gint32 index = tvb_get_gint32(tvb_content, xplane_DATA_STRUCT_LENGTH * i, ENC_LITTLE_ENDIAN);
        proto_tree* xplane_content_tree = proto_tree_add_subtree_format(xplane_data_tree, tvb_content, xplane_DATA_STRUCT_LENGTH * i, xplane_DATA_STRUCT_LENGTH, ett_xplane_data, NULL, "DATA Index: %d", index);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_index, tvb_content, (xplane_DATA_STRUCT_LENGTH * i), 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_a, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_b, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_c, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_d, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_e, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_f, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 24, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_g, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 28, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_data_h, tvb_content, (xplane_DATA_STRUCT_LENGTH * i) + 32, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

static int dissect_xplane_dcoc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    guint recordCount = tvb_captured_length(tvb_content) / xplane_DATA_INDEX_LENGTH;

    proto_item* xplane_dcoc_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_dcoc_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_dcoc_tree = proto_item_add_subtree(xplane_dcoc_item, ett_xplane_dcoc);
    proto_item* xplane_header_item = proto_tree_add_item(xplane_dcoc_tree, hf_xplane_dcoc_header, tvb, 0, 4, ENC_ASCII);
    proto_item_append_text(xplane_header_item, " count=%u", recordCount);

    for (guint32 i = 0; i < recordCount; i++)
        proto_tree_add_item(xplane_dcoc_tree, hf_xplane_dcoc_id, tvb_content, i * xplane_DATA_INDEX_LENGTH, xplane_DATA_INDEX_LENGTH, ENC_LITTLE_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Count=%u", recordCount);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_dref(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* dref = NULL;

    proto_item* xplane_dref_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_dref_item, ", Length=%u bytes.", tvb_captured_length(tvb));

    proto_tree* xplane_dref_tree = proto_item_add_subtree(xplane_dref_item, ett_xplane_dref);
    proto_tree_add_item(xplane_dref_tree, hf_xplane_dref_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_dref_tree, hf_xplane_dref_value, tvb_content, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_string(xplane_dref_tree, hf_xplane_dref_dataref, tvb_content, 4, -1, ENC_ASCII, wmem_packet_scope(), &dref);

    col_append_fstr(pinfo->cinfo, COL_INFO, " DRef=%s", dref);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_dsel(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    guint recordCount = tvb_captured_length(tvb_content) / xplane_DATA_INDEX_LENGTH;

    proto_item* xplane_dsel_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_dsel_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_dsel_tree = proto_item_add_subtree(xplane_dsel_item, ett_xplane_dsel);
    proto_item* xplane_header_item = proto_tree_add_item(xplane_dsel_tree, hf_xplane_dsel_header, tvb, 0, 4, ENC_ASCII);
    proto_item_append_text(xplane_header_item, " Count=%u", recordCount);

    for (guint32 i = 0; i < recordCount; i++)
        proto_tree_add_item(xplane_dsel_tree, hf_xplane_dsel_id, tvb_content, i * 4, 4, ENC_LITTLE_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Count=%u", recordCount);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_fail(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* systemid = NULL;

    proto_item* xplane_fail_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_fail_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_fail_tree = proto_item_add_subtree(xplane_fail_item, ett_xplane_fail);
    proto_tree_add_item(xplane_fail_tree, hf_xplane_fail_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_fail_tree, hf_xplane_fail_id, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &systemid);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%s", systemid);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_flir_in(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* framerate = NULL;

    proto_item* xplane_flir_in_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_flir_in_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_flir_in_tree = proto_item_add_subtree(xplane_flir_in_item, ett_xplane_flir_in);
    proto_tree_add_item(xplane_flir_in_tree, hf_xplane_flir_in_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_flir_in_tree, hf_xplane_flir_in_framerate, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &framerate);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Framerate=%s", framerate);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_flir_out(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    guint32 frameindex, framecount;

    proto_item* xplane_flir_out_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_flir_out_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_flir_out_tree = proto_item_add_subtree(xplane_flir_out_item, ett_xplane_flir_out);
    proto_tree_add_item(xplane_flir_out_tree, hf_xplane_flir_out_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_flir_out_tree, hf_xplane_flir_out_height, tvb_content, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_flir_out_tree, hf_xplane_flir_out_width, tvb_content, 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(xplane_flir_out_tree, hf_xplane_flir_out_frameindex, tvb_content, 4, 1, ENC_NA, &frameindex);
    proto_tree_add_item_ret_uint(xplane_flir_out_tree, hf_xplane_flir_out_framecount, tvb_content, 5, 1, ENC_NA, &framecount);
    proto_tree_add_item(xplane_flir_out_tree, hf_xplane_flir_out_imagedata, tvb_content, 6, -1, ENC_ASCII);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Index=%u Count=%u", frameindex, framecount);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_ise4(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_ise4_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_ise4_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_ise4_tree = proto_item_add_subtree(xplane_ise4_item, ett_xplane_ise4);
    proto_tree_add_item(xplane_ise4_tree, hf_xplane_ise4_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_ise4_tree, hf_xplane_ise4_machinetype, tvb_content, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_ise4_tree, hf_xplane_ise4_address, tvb_content, 4, 16, ENC_ASCII);
    proto_tree_add_item(xplane_ise4_tree, hf_xplane_ise4_port, tvb_content, 20, 8, ENC_ASCII);
    proto_tree_add_item(xplane_ise4_tree, hf_xplane_ise4_enabled, tvb_content, 28, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_ise6(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_ise6_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_ise6_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_ise6_tree = proto_item_add_subtree(xplane_ise6_item, ett_xplane_ise6);
    proto_tree_add_item(xplane_ise6_tree, hf_xplane_ise6_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_ise6_tree, hf_xplane_ise6_machinetype, tvb_content, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_ise6_tree, hf_xplane_ise6_address, tvb_content, 4, 65, ENC_ASCII);
    proto_tree_add_item(xplane_ise6_tree, hf_xplane_ise6_port, tvb_content, 69, 6, ENC_ASCII);
    proto_tree_add_item(xplane_ise6_tree, hf_xplane_ise6_enabled, tvb_content, 76, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_lsnd(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    gint32 index;
    const guint8* filename = NULL;

    proto_item* xplane_lsnd_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_lsnd_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_lsnd_tree = proto_item_add_subtree(xplane_lsnd_item, ett_xplane_lsnd);
    proto_tree_add_item(xplane_lsnd_tree, hf_xplane_lsnd_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_lsnd_tree, hf_xplane_lsnd_index, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &index);
    proto_tree_add_item(xplane_lsnd_tree, hf_xplane_lsnd_speed, tvb_content, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_lsnd_tree, hf_xplane_lsnd_volume, tvb_content, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_string(xplane_lsnd_tree, hf_xplane_lsnd_filename, tvb_content, 12, -1, ENC_ASCII, wmem_packet_scope(), &filename);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Index=%u Filename=%s", index, filename);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_nfal(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* navaid = NULL;

    proto_item* xplane_nfal_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_nfal_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_nfal_tree = proto_item_add_subtree(xplane_nfal_item, ett_xplane_nfal);
    proto_tree_add_item(xplane_nfal_tree, hf_xplane_nfal_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_nfal_tree, hf_xplane_nfal_navaidcode, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &navaid);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Navaid=%s", navaid);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_nrec(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* navaid = NULL;

    proto_item* xplane_nrec_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_nrec_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_nrec_tree = proto_item_add_subtree(xplane_nrec_item, ett_xplane_nrec);
    proto_tree_add_item(xplane_nrec_tree, hf_xplane_nrec_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_nrec_tree, hf_xplane_nrec_navaidcode, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &navaid);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Navaid=%s", navaid);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_objl(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    gint32 id;

    proto_item* xplane_objl_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_objl_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_objl_tree = proto_item_add_subtree(xplane_objl_item, ett_xplane_objl);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_objl_tree, hf_xplane_objl_index, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &id);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_padding1, tvb_content, 4, 4, ENC_NA);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_latitude, tvb_content, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_longitude, tvb_content, 16, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_elevation, tvb_content, 24, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_psi, tvb_content, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_theta, tvb_content, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_phi, tvb_content, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_onground, tvb_content, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_smokesize, tvb_content, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_objl_tree, hf_xplane_objl_padding2, tvb_content, 52, 4, ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%d", id);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_objn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    gint32 id = 0;
    const guint8* filename = NULL;

    proto_item* xplane_objn_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_objn_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_objn_tree = proto_item_add_subtree(xplane_objn_item, ett_xplane_objn);
    proto_tree_add_item(xplane_objn_tree, hf_xplane_objn_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_objn_tree, hf_xplane_objn_index, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &id);
    proto_tree_add_item_ret_string(xplane_objn_tree, hf_xplane_objn_filename, tvb_content, 4, -1, ENC_ASCII, wmem_packet_scope(), &filename);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%d Filename=%s", id, filename);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_prel(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_prel_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_prel_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_prel_tree = proto_item_add_subtree(xplane_prel_item, ett_xplane_prel);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_starttype, tvb_content, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_aircraftindex, tvb_content, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_ICAO, tvb_content, 8, 8, ENC_ASCII);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_runwayindex, tvb_content, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_runwaydirection, tvb_content, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_latitude, tvb_content, 24, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_longitude, tvb_content, 32, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_elevation, tvb_content, 40, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_trueheading, tvb_content, 48, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_prel_tree, hf_xplane_prel_speed, tvb_content, 56, 8, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_quit(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_quit_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_quit_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_quit_tree = proto_item_add_subtree(xplane_quit_item, ett_xplane_quit);
    proto_tree_add_item(xplane_quit_tree, hf_xplane_quit_header, tvb, 0, 4, ENC_ASCII);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_radr_in(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* pointcount = NULL;

    proto_item* xplane_radr_in_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_radr_in_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_radr_in_tree = proto_item_add_subtree(xplane_radr_in_item, ett_xplane_radr_in);
    proto_tree_add_item(xplane_radr_in_tree, hf_xplane_radr_in_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_radr_in_tree, hf_xplane_radr_in_pointcount, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &pointcount);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Points=%s", pointcount);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_radr_out(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    guint recordCount = (tvb_captured_length(tvb) - 5) / xplane_RADR_STRUCT_LENGTH;

    proto_item* xplane_radr_out_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_radr_out_item, " Length=%u, Count=%u", tvb_captured_length(tvb), recordCount);

    proto_tree* xplane_radr_out_tree = proto_item_add_subtree(xplane_radr_out_item, ett_xplane_radr_out);
    proto_tree_add_item(xplane_radr_out_tree, hf_xplane_radr_out_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    for (guint32 i = 0; i < recordCount; i++)
    {
        proto_tree* xplane_content_tree = proto_tree_add_subtree_format(xplane_radr_out_tree, tvb_content, xplane_RADR_STRUCT_LENGTH * i, xplane_RADR_STRUCT_LENGTH, ett_xplane_radr_out, NULL, "Element: %d", i);
        proto_tree_add_item(xplane_content_tree, hf_xplane_radr_out_longitude, tvb_content, (xplane_RADR_STRUCT_LENGTH * i), 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_radr_out_latitude, tvb_content, (xplane_RADR_STRUCT_LENGTH * i) + 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_radr_out_precipitation, tvb_content, (xplane_RADR_STRUCT_LENGTH * i) + 8, 1, ENC_NA);
        proto_tree_add_item(xplane_content_tree, hf_xplane_radr_out_height, tvb_content, (xplane_RADR_STRUCT_LENGTH * i) + 9, 4, ENC_LITTLE_ENDIAN);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Count=%u", recordCount);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_reco(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_reco_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_reco_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_reco_tree = proto_item_add_subtree(xplane_reco_item, ett_xplane_reco);
    proto_tree_add_item(xplane_reco_tree, hf_xplane_reco_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_reco_tree, hf_xplane_reco_id, tvb_content, 0, -1, ENC_ASCII);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_rese(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_rese_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_rese_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_rese_tree = proto_item_add_subtree(xplane_rese_item, ett_xplane_rese);
    proto_tree_add_item(xplane_rese_tree, hf_xplane_rese_header, tvb, 0, 4, ENC_ASCII);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_rpos_in(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* frequency = 0;

    proto_item* xplane_rpos_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_rpos_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_rpos_tree = proto_item_add_subtree(xplane_rpos_item, ett_xplane_rpos_in);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_in_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_string(xplane_rpos_tree, hf_xplane_rpos_in_frequency, tvb_content, 0, -1, ENC_ASCII, wmem_packet_scope(), &frequency);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Frequency=%s", frequency);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_rpos_out(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_rpos_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_rpos_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_rpos_tree = proto_item_add_subtree(xplane_rpos_item, ett_xplane_rpos_out);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_longitude, tvb_content, 0, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_latitude, tvb_content, 8, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_elevation, tvb_content, 16, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_height, tvb_content, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_theta, tvb_content, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_psi, tvb_content, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_phi, tvb_content, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_vx, tvb_content, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_vy, tvb_content, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_vz, tvb_content, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_rollrate, tvb_content, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_pitchrate, tvb_content, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_rpos_tree, hf_xplane_rpos_out_yawrate, tvb_content, 60, 4, ENC_LITTLE_ENDIAN);

    col_append_str(pinfo->cinfo, COL_INFO, " out");

    return tvb_captured_length(tvb);
}

static int dissect_xplane_rref_in(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* rref = NULL;
    gint32 id, frequency;

    proto_item* xplane_rref_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_rref_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_rref_tree = proto_item_add_subtree(xplane_rref_item, ett_xplane_rref_in);
    proto_tree_add_item(xplane_rref_tree, hf_xplane_rref_in_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_rref_tree, hf_xplane_rref_in_frequency, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &frequency);
    proto_tree_add_item_ret_int(xplane_rref_tree, hf_xplane_rref_in_id, tvb_content, 4, 4, ENC_LITTLE_ENDIAN, &id);
    proto_tree_add_item_ret_string(xplane_rref_tree, hf_xplane_rref_in_dataref, tvb_content, 8, 400, ENC_ASCII, wmem_packet_scope(), &rref);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%d, Freq=%d, RRef=%s", id, frequency, rref);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_rref_out(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    guint recordCount = (tvb_captured_length(tvb) - 5) / 8;

    proto_item* xplane_rref_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_rref_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_rref_tree = proto_item_add_subtree(xplane_rref_item, ett_xplane_rref_out);
    proto_item* xplane_header_item = proto_tree_add_item(xplane_rref_tree, hf_xplane_rref_out_header, tvb, 0, 4, ENC_ASCII);
    proto_item_append_text(xplane_header_item, " Count=%d", recordCount);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    for (guint32 i = 0; i < recordCount; i++)
    {
        gint32 id = tvb_get_gint32(tvb_content, 8 * i, ENC_LITTLE_ENDIAN);
        proto_tree* xplane_content_tree = proto_tree_add_subtree_format(xplane_rref_tree, tvb_content, 8 * i, 8, ett_xplane_rref_out, NULL, "RREF Id: %d", id);
        proto_tree_add_item(xplane_content_tree, hf_xplane_rref_out_id, tvb_content, 8 * i, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(xplane_content_tree, hf_xplane_rref_out_value, tvb_content, (8 * i) + 4, 4, ENC_LITTLE_ENDIAN);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Count=%d", recordCount);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_shut(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_shut_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_shut_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_shut_tree = proto_item_add_subtree(xplane_shut_item, ett_xplane_shut);
    proto_tree_add_item(xplane_shut_tree, hf_xplane_shut_header, tvb, 0, 4, ENC_ASCII);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_simo(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    gint32 action;
    const guint8* filename = NULL;

    proto_item* xplane_simo_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_simo_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_simo_tree = proto_item_add_subtree(xplane_simo_item, ett_xplane_simo);
    proto_tree_add_item(xplane_simo_tree, hf_xplane_simo_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_simo_tree, hf_xplane_simo_action, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &action);
    proto_tree_add_item_ret_string(xplane_simo_tree, hf_xplane_simo_filename, tvb_content, 4, -1, ENC_ASCII, wmem_packet_scope(), &filename);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Action=%d Filename=%s", action, filename);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_soun(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    const guint8* filename = NULL;

    proto_item* xplane_soun_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_soun_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_soun_tree = proto_item_add_subtree(xplane_soun_item, ett_xplane_soun);
    proto_tree_add_item(xplane_soun_tree, hf_xplane_soun_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_soun_tree, hf_xplane_soun_speed, tvb_content, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_soun_tree, hf_xplane_soun_volume, tvb_content, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_string(xplane_soun_tree, hf_xplane_soun_filename, tvb_content, 8, -1, ENC_ASCII, wmem_packet_scope(), &filename);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Filename=%s", filename);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_ssnd(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    gint32 index = 0;
    const guint8* filename = NULL;

    proto_item* xplane_ssnd_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_ssnd_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_ssnd_tree = proto_item_add_subtree(xplane_ssnd_item, ett_xplane_ssnd);
    proto_tree_add_item(xplane_ssnd_tree, hf_xplane_ssnd_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item_ret_int(xplane_ssnd_tree, hf_xplane_ssnd_index, tvb_content, 0, 4, ENC_LITTLE_ENDIAN, &index);
    proto_tree_add_item(xplane_ssnd_tree, hf_xplane_ssnd_speed, tvb_content, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_ssnd_tree, hf_xplane_ssnd_volume, tvb_content, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_string(xplane_ssnd_tree, hf_xplane_ssnd_filename, tvb_content, 12, -1, ENC_ASCII, wmem_packet_scope(), &filename);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Index=%d Filename=%s", index, filename);

    return tvb_captured_length(tvb);
}

static int dissect_xplane_ucoc(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    guint recordCount = tvb_captured_length(tvb_content) / 4;

    proto_item* xplane_ucoc_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_ucoc_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_ucoc_tree = proto_item_add_subtree(xplane_ucoc_item, ett_xplane_ucoc);
    proto_item* xplane_header_item = proto_tree_add_item(xplane_ucoc_tree, hf_xplane_ucoc_header, tvb, 0, 4, ENC_ASCII);
    proto_item_append_text(xplane_header_item, " Count=%u", recordCount);

    for (guint32 i = 0; i < recordCount; i++)
    {
        proto_tree_add_item(xplane_ucoc_tree, hf_xplane_ucoc_id, tvb_content, i * 4, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}


static int dissect_xplane_usel(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    guint recordCount = tvb_captured_length(tvb_content) / 4;

    proto_item* xplane_usel_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_usel_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_usel_tree = proto_item_add_subtree(xplane_usel_item, ett_xplane_usel);
    proto_item* xplane_header_item = proto_tree_add_item(xplane_usel_tree, hf_xplane_usel_header, tvb, 0, 4, ENC_ASCII);
    proto_item_append_text(xplane_header_item, " Count=%u", recordCount);

    for (guint32 i = 0; i < recordCount; i++)
    {
        proto_tree_add_item(xplane_usel_tree, hf_xplane_usel_id, tvb_content, i * 4, 4, ENC_LITTLE_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

static int dissect_xplane_vehx(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data _U_)
{
    proto_item* xplane_vehx_item = proto_tree_add_item(tree, proto_xplane, tvb, 0, -1, ENC_NA);
    proto_item_append_text(xplane_vehx_item, " Length=%u", tvb_captured_length(tvb));

    proto_tree* xplane_vehx_tree = proto_item_add_subtree(xplane_vehx_item, ett_xplane_vehx);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_header, tvb, 0, 4, ENC_ASCII);

    tvbuff_t* tvb_content = tvb_new_subset_length(tvb, xplane_HEADER_LENGTH, -1);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_id, tvb_content, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_latitude, tvb_content, 4, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_longitude, tvb_content, 12, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_elevation, tvb_content, 20, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_heading, tvb_content, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_pitch, tvb_content, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(xplane_vehx_tree, hf_xplane_vehx_roll, tvb_content, 36, 4, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}

static gboolean validate_packet(tvbuff_t* tvb, packet_info* pinfo)
{
    guint8* bytes = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_ASCII | ENC_NA);
    guint packet_length = tvb_captured_length(tvb);

    return ((strcmp(bytes, "ACFN") == 0 && packet_length == xplane_ACFN_PACKET_LENGTH) ||
        (strcmp(bytes, "ACPR") == 0 && packet_length == xplane_ACPR_PACKET_LENGTH) ||
        (strcmp(bytes, "ALRT") == 0 && packet_length == xplane_ALRT_PACKET_LENGTH) ||
        (strcmp(bytes, "BECN") == 0 && pinfo->destport == xplane_pref_becn_port) ||
        strcmp(bytes, "CMND") == 0 ||
        (strcmp(bytes, "DATA") == 0 && ((packet_length - 5) % xplane_DATA_STRUCT_LENGTH) == 0) ||
        (strcmp(bytes, "DCOC") == 0 && ((packet_length - 5) % xplane_DATA_INDEX_LENGTH) == 0) ||
        (strcmp(bytes, "DREF") == 0 && packet_length == xplane_DREF_PACKET_LENGTH) ||
        (strcmp(bytes, "DSEL") == 0 && ((packet_length - 5) % xplane_DATA_INDEX_LENGTH) == 0) ||
        strcmp(bytes, "FAIL") == 0 ||
        strcmp(bytes, "FLIR") == 0 ||
        (strcmp(bytes, "ISE4") == 0 && packet_length == xplane_ISE4_PACKET_LENGTH) ||
        (strcmp(bytes, "ISE6") == 0 && packet_length == xplane_ISE6_PACKET_LENGTH) ||
        (strcmp(bytes, "LSND") == 0 && packet_length == xplane_LSND_PACKET_LENGTH) ||
        strcmp(bytes, "NFAL") == 0 ||
        strcmp(bytes, "NREC") == 0 ||
        (strcmp(bytes, "OBJL") == 0 && packet_length == xplane_OBJL_PACKET_LENGTH) ||
        (strcmp(bytes, "OBJN") == 0 && packet_length == xplane_OBJN_PACKET_LENGTH) ||
        (strcmp(bytes, "PREL") == 0 && packet_length == xplane_PREL_PACKET_LENGTH) ||
        (strcmp(bytes, "QUIT") == 0 && packet_length == xplane_QUIT_PACKET_LENGTH) ||
        (strcmp(bytes, "RADR") == 0 && (packet_length < 10 || (packet_length - 5) % xplane_RADR_STRUCT_LENGTH == 0)) ||
        strcmp(bytes, "RECO") == 0 ||
        (strcmp(bytes, "RESE") == 0 && packet_length == xplane_RESE_PACKET_LENGTH) ||
        (strcmp(bytes, "RPOS") == 0 && (packet_length < 10 || packet_length == xplane_RPOS_OUT_PACKET_LENGTH)) ||
        (strcmp(bytes, "RREF") == 0 && (packet_length == xplane_RREF_IN_PACKET_LENGTH || (packet_length - 5) % 8 == 0)) ||
        (strcmp(bytes, "SHUT") == 0 && packet_length == xplane_SHUT_PACKET_LENGTH) ||
        strcmp(bytes, "SIMO") == 0 ||
        (strcmp(bytes, "SOUN") == 0 && packet_length == xplane_SOUN_PACKET_LENGTH) ||
        (strcmp(bytes, "SSND") == 0 && packet_length == xplane_SSND_PACKET_LENGTH) ||
        (strcmp(bytes, "UCOC") == 0 && ((packet_length - 5) % xplane_DATA_INDEX_LENGTH) == 0) ||
        (strcmp(bytes, "USEL") == 0 && ((packet_length - 5) % xplane_DATA_INDEX_LENGTH) == 0) ||
        (strcmp(bytes, "VEHX") == 0 && packet_length == xplane_VEHX_PACKET_LENGTH));
}

static int dissect_xplane(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    if (tvb_reported_length(tvb) < xplane_MIN_PACKET_LENGTH || tvb_captured_length(tvb) < xplane_MIN_PACKET_LENGTH)
        return 0;

    if (!validate_packet(tvb, pinfo))
        return 0;

    guint8* bytes = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 4, ENC_ASCII | ENC_NA);
    gchar* bytes_lower = wmem_ascii_strdown(wmem_packet_scope(), bytes, 4);

    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "xplane.%s", bytes_lower);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "X-Plane (%s)", bytes);

    if (strcmp(bytes, "ACFN") == 0)
        return dissect_xplane_acfn(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "ACPR") == 0)
        return dissect_xplane_acpr(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "ALRT") == 0)
        return dissect_xplane_alrt(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "BECN") == 0)
        return dissect_xplane_becn(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "CMND") == 0)
        return dissect_xplane_cmnd(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "DATA") == 0)
        return dissect_xplane_data(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "DCOC") == 0)
        return dissect_xplane_dcoc(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "DREF") == 0)
        return dissect_xplane_dref(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "DSEL") == 0)
        return dissect_xplane_dsel(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "FAIL") == 0)
        return dissect_xplane_fail(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "FLIR") == 0)
    {
        if (tvb_captured_length(tvb) < 20)
            return dissect_xplane_flir_in(tvb, pinfo, tree, data);
        else
            return dissect_xplane_flir_out(tvb, pinfo, tree, data);
    }
    else if (strcmp(bytes, "ISE4") == 0)
        return dissect_xplane_ise4(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "ISE6") == 0)
        return dissect_xplane_ise6(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "LSND") == 0)
        return dissect_xplane_lsnd(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "NFAL") == 0)
        return dissect_xplane_nfal(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "NREC") == 0)
        return dissect_xplane_nrec(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "OBJL") == 0)
        return dissect_xplane_objl(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "OBJN") == 0)
        return dissect_xplane_objn(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "PREL") == 0)
        return dissect_xplane_prel(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "QUIT") == 0)
        return dissect_xplane_quit(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "RADR") == 0)
    {
        if (tvb_captured_length(tvb) < 10)
            return dissect_xplane_radr_in(tvb, pinfo, tree, data);
        else
            return dissect_xplane_radr_out(tvb, pinfo, tree, data);
    }
    else if (strcmp(bytes, "RECO") == 0)
        return dissect_xplane_reco(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "RESE") == 0)
        return dissect_xplane_rese(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "RPOS") == 0)
    {
        if (tvb_captured_length(tvb) < 10)
            return dissect_xplane_rpos_in(tvb, pinfo, tree, data);
        else if (tvb_captured_length(tvb) == 69)
            return dissect_xplane_rpos_out(tvb, pinfo, tree, data);
        else
            return 0;
    }
    else if (strcmp(bytes, "RREF") == 0)
    {
        if (tvb_captured_length(tvb) == xplane_RREF_IN_PACKET_LENGTH)
            return dissect_xplane_rref_in(tvb, pinfo, tree, data);
        else
            return dissect_xplane_rref_out(tvb, pinfo, tree, data);
    }
    else if (strcmp(bytes, "SHUT") == 0)
        return dissect_xplane_shut(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "SIMO") == 0)
        return dissect_xplane_simo(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "SOUN") == 0)
        return dissect_xplane_soun(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "SSND") == 0)
        return dissect_xplane_ssnd(tvb, pinfo, tree, data);
    else if (strcmp(bytes, "UCOC") == 0)
    {
        if (((tvb_captured_length(tvb) - 5) % 4) != 0)
            return 0;
        return dissect_xplane_ucoc(tvb, pinfo, tree, data);
    }
    else if (strcmp(bytes, "USEL") == 0)
    {
        if (((tvb_captured_length(tvb) - 5) % 4) != 0)
            return 0;
        return dissect_xplane_usel(tvb, pinfo, tree, data);
    }
    else if (strcmp(bytes, "VEHX") == 0)
        return dissect_xplane_vehx(tvb, pinfo, tree, data);

    //Packet Header not recognised - return that we didn't process it.
    return 0;
}

void proto_register_xplane(void)
{
    static hf_register_info hf_xplane_acfn[] =
    {
        { &hf_xplane_acfn_header,   { "Header",     "xplane.acfn",          FT_STRING,     STR_ASCII,  NULL,   0,  "ACFN - Load an AI aircraft into the select slot.",  HFILL}},
        { &hf_xplane_acfn_index,    { "Index",      "xplane.acfn.index",    FT_INT32,      BASE_DEC,   NULL,   0,  "Aircraft Index (0=Own Plane, 1->19 = AI Plane).",        HFILL}},
        { &hf_xplane_acfn_path,     { "Path",       "xplane.acfn.path",     FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The .acf filename relative to X-Plane's home folder. Use Unix style '/' directory seperators.",         HFILL}},
        { &hf_xplane_acfn_padding,  { "Padding",    "xplane.acfn.padding",  FT_BYTES,      BASE_NONE,  NULL,   0,  "2 bytes of padding",      HFILL}},
        { &hf_xplane_acfn_livery,   { "Livery",     "xplane.acfn.livery",   FT_INT32,      BASE_DEC,   NULL,   0,  "Livery ID. 0->x in alphabetical order for the liveries listed in the aircraft folder. Adding a new livery may change the order.",    HFILL}}
    };
    static hf_register_info hf_xplane_acpr[] =
    {
        { &hf_xplane_acpr_header,           { "Header",             "xplane.acpr",                  FT_STRINGZ,    STR_ASCII,  NULL,   0,  "ACPR - Load and Position an AI into the selected slot.",      HFILL}},
        { &hf_xplane_acpr_index,            { "Index",              "xplane.acpr.index",            FT_INT32,      BASE_DEC,   NULL,   0,  "Aircraft Index (0=Own Plane, 1->19 = AI Plane).",            HFILL}},
        { &hf_xplane_acpr_path,             { "Path",               "xplane.acpr.path",             FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The path relative to X-Plane's home folder. Use Unix style / directory seperators.",             HFILL}},
        { &hf_xplane_acpr_padding,          { "Padding",            "xplane.acpr.padding",          FT_BYTES,      BASE_NONE,  NULL,   0,  "2 bytes of padding.",          HFILL}},
        { &hf_xplane_acpr_livery,           { "Livery",             "xplane.acpr.livery",           FT_INT32,      BASE_DEC,   NULL,   0,  "Livery ID. 0->n in alphabetical order for the liveries listed in the aircraft folder. Adding a new livery may change the order.",    HFILL}},
        { &hf_xplane_acpr_starttype,        { "Start Type",         "xplane.acpr.starttype",        FT_INT32,      BASE_DEC,   VALS(vals_StartType),   0,  "The Start type such as runway, LatLong, etc.",       HFILL}},
        { &hf_xplane_acpr_aircraftindex,    { "Aircraft Index",     "xplane.acpr.aircraftindex",    FT_INT32,      BASE_DEC,   NULL,   0,  "Aircraft Index (unused - see the Index entry).",   HFILL}},
        { &hf_xplane_acpr_ICAO,             { "ICAO",               "xplane.acpr.ICAO",             FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "Airport / NavAid code to place the aircraft at. Note: Max 7 chars as the packet's struct is 8 chars including the ending '\0'.",             HFILL}},
        { &hf_xplane_acpr_runwayindex,      { "Runway Index",       "xplane.acpr.runwayindex",      FT_INT32,      BASE_DEC,   NULL,   0,  "Runway Index. 0 based on the order listed in the apt.dat file. Note 09L/27R will be one runway. See Runway direction for which end to start from.",     HFILL}},
        { &hf_xplane_acpr_runwaydirection,  { "Runway Direction",   "xplane.acpr.runwaydirection",  FT_INT32,      BASE_DEC,   NULL,   0,  "Runway Direction. 0 (Normal) or 1 (Reversed). So for 09L/27R use 1 for 27R. For a Helipad this reverses the helipad's heading.", HFILL}},
        { &hf_xplane_acpr_latitude,         { "Latitude",           "xplane.acpr.latitude",         FT_DOUBLE,     BASE_NONE,  NULL,   0,  "Latitude - Ignored if the Start Type is not a LatLong.",         HFILL}},
        { &hf_xplane_acpr_longitude,        { "Longitude",          "xplane.acpr.longitude",        FT_DOUBLE,     BASE_NONE,  NULL,   0,  "Longitude - Ignored if the Start Type is not a LatLong.",        HFILL}},
        { &hf_xplane_acpr_elevation,        { "Elevation",          "xplane.acpr.elevation",        FT_DOUBLE,     BASE_NONE,  NULL,   0,  "Elevation (Metres above Mean Sea Level) - Ignored if the Start Type is not a LatLong.",        HFILL}},
        { &hf_xplane_acpr_trueheading,      { "True Heading",       "xplane.acpr.trueheading",      FT_DOUBLE,     BASE_NONE,  NULL,   0,  "True Heading -  Ignored if the Start Type is not a LatLong.",     HFILL}},
        { &hf_xplane_acpr_speed,            { "Speed (m/s)",        "xplane.acpr.speed",            FT_DOUBLE,     BASE_NONE,  NULL,   0,  "Speed (Metres per Second) - Ignored if the Start Type is not a LatLong.",            HFILL}},
    };
    static hf_register_info hf_xplane_alrt[] =
    {
        { &hf_xplane_alrt_header,   { "Header",         "xplane.alrt",          FT_STRINGZ,    STR_ASCII,  NULL,   0,  "ALRT - Display on Alert Message in X-Plane",   HFILL}},
        { &hf_xplane_alrt_line1,    { "Line 1",         "xplane.alrt.line1",    FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The first line to display in the alert.",      HFILL}},
        { &hf_xplane_alrt_line2,    { "Line 2",         "xplane.alrt.line2",    FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The second line to display in the alert.",     HFILL}},
        { &hf_xplane_alrt_line3,    { "Line 3",         "xplane.alrt.line3",    FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The third line to display in the alert.",      HFILL}},
        { &hf_xplane_alrt_line4,    { "Line 4",         "xplane.alrt.line4",    FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The fourth line to display in the alert.",     HFILL}}
    };
    static hf_register_info hf_xplane_becn[] =
    {
        { &hf_xplane_becn_header,   { "Header",         "xplane.becn",          FT_STRINGZ, STR_ASCII,  NULL,   0,  "Beacon Header",    HFILL}},
        { &hf_xplane_becn_major,    { "Major Version",  "xplane.becn.major",    FT_UINT8,   BASE_DEC,   NULL,   0,  "The Major Version for this BECN packet.",    HFILL}},
        { &hf_xplane_becn_minor,    { "Minor Version",  "xplane.becn.minor",    FT_UINT8,   BASE_DEC,   NULL,   0,  "The Major Version for this BECN packet.",    HFILL}},
        { &hf_xplane_becn_hostid,   { "Host ID",        "xplane.becn.hostid",   FT_INT32,   BASE_DEC,   VALS(vals_Becn_HostID),   0,  "The application type. 1=X-Plane, 2=Planemaker.",          HFILL}},
        { &hf_xplane_becn_version,  { "Version",        "xplane.becn.version",  FT_INT32,   BASE_DEC,   NULL,   0,  "Version Number xxyyzz xx=Major, yy=Minor, zz=Release",   HFILL}},
        { &hf_xplane_becn_role,     { "Role",           "xplane.becn.role",     FT_UINT32,  BASE_DEC,   VALS(vals_MachineRole), 0,"Role the remote computer is undertaking, eg Master / External Visual / IOS", HFILL}},
        { &hf_xplane_becn_port,     { "Port",           "xplane.becn.port",     FT_UINT32,  BASE_DEC,   NULL,   0,  "Port the remote computer is listening on.",             HFILL}},
        { &hf_xplane_becn_name,     { "Computer name",  "xplane.becn.name",     FT_STRINGZ, STR_ASCII,  NULL,   0,  "Remote Computer Name.",    HFILL}},
        { &hf_xplane_becn_newport,  { "New Port",       "xplane.becn.newport",  FT_UINT16,  BASE_DEC,   NULL,   0,  "New port the remote computer will be listening on.",         HFILL}}
    };
    static hf_register_info hf_xplane_cmnd[] =
    {
        { &hf_xplane_cmnd_header,   { "Header",     "xplane.cmnd",          FT_STRINGZ,    STR_ASCII,  NULL,   0,  "CMND Header",  HFILL}},
        { &hf_xplane_cmnd_command,  { "Command",    "xplane.cmnd.command",  FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The command to be executed", HFILL}}
    };
    static hf_register_info hf_xplane_data[] =
    {
        { &hf_xplane_data_header,   { "Header", "xplane.data",          FT_STRINGZ, STR_ASCII,  NULL,   0,  "DATA Header",  HFILL}},
        { &hf_xplane_data_index,    { "Index",  "xplane.data.index",    FT_INT32,   BASE_DEC,   NULL,   0,  "DATA Index",   HFILL}},
        { &hf_xplane_data_a,        { "A",      "xplane.data.a",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item A",       HFILL}},
        { &hf_xplane_data_b,        { "B",      "xplane.data.b",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item B",       HFILL}},
        { &hf_xplane_data_c,        { "C",      "xplane.data.c",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item C",       HFILL}},
        { &hf_xplane_data_d,        { "D",      "xplane.data.d",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item D",       HFILL}},
        { &hf_xplane_data_e,        { "E",      "xplane.data.e",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item E",       HFILL}},
        { &hf_xplane_data_f,        { "F",      "xplane.data.f",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item F",       HFILL}},
        { &hf_xplane_data_g,        { "G",      "xplane.data.g",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item G",       HFILL}},
        { &hf_xplane_data_h,        { "H",      "xplane.data.h",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Item H",       HFILL}}
    };
    static hf_register_info hf_xplane_dcoc[] =
    {
        { &hf_xplane_dcoc_header,   { "Header", "xplane.dcoc",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "DCOC Header",  HFILL}},
        { &hf_xplane_dcoc_id,       { "Id",     "xplane.dcoc.id",   FT_INT32,   BASE_DEC,   NULL,   0,  "A Data row id.",      HFILL}}
    };
    static hf_register_info hf_xplane_dref[] =
    {
        { &hf_xplane_dref_header,   { "Header",     "xplane.dref",          FT_STRINGZ,    STR_ASCII,  NULL,   0,  "DREF Header",  HFILL}},
        { &hf_xplane_dref_value,    { "Value",      "xplane.dref.value",    FT_FLOAT,      BASE_NONE,  NULL,   0,  "The value to set the dataref to.",        HFILL}},
        { &hf_xplane_dref_dataref,  { "Dataref",    "xplane.dref.dataref",  FT_STRINGZPAD, STR_ASCII,  NULL,   0,  "The dataref to be set.",      HFILL}}
    };
    static hf_register_info hf_xplane_dsel[] =
    {
        { &hf_xplane_dsel_header,   { "Header", "xplane.dsel",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "DSEL Header",  HFILL}},
        { &hf_xplane_dsel_id,       { "Id",     "xplane.dsel.id",   FT_INT32,   BASE_DEC,   NULL,   0,  "A Data row id",      HFILL}}
    };
    static hf_register_info hf_xplane_fail[] =
    {
        { &hf_xplane_fail_header,   { "Header", "xplane.fail",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "FAIL Header",  HFILL}},
        { &hf_xplane_fail_id,       { "Id",     "xplane.fail.id",   FT_STRINGZ, STR_ASCII,  NULL,   0,  "The id of the Plane System to fail.",      HFILL}}
    };
    static hf_register_info hf_xplane_flir_in[] =
    {
        { &hf_xplane_flir_in_header,        { "Header",         "xplane.flir",              FT_STRINGZ, STR_ASCII, NULL,   0,  "FLIR Header (in)",  HFILL}},
        { &hf_xplane_flir_in_framerate,     { "Frame Rate",     "xplane.flir.framerate",    FT_STRINGZ, STR_ASCII, NULL,   0,  "The requested Frame Rate for the returned images.",   HFILL}}
    };
    static hf_register_info hf_xplane_flir_out[] =
    {
        { &hf_xplane_flir_out_header,       { "Header",         "xplane.flir",              FT_STRINGZ, STR_ASCII,  NULL,   0,  "FLIR Header (out)",    HFILL}},
        { &hf_xplane_flir_out_height,       { "Height",         "xplane.flir.height",       FT_INT16, BASE_DEC,     NULL,   0,  "Image Height",         HFILL}},
        { &hf_xplane_flir_out_width,        { "Width",          "xplane.flir.width",        FT_INT16, BASE_DEC,     NULL,   0,  "Image Width",          HFILL}},
        { &hf_xplane_flir_out_frameindex,   { "Frame Index",    "xplane.flir.frameindex",   FT_UINT8, BASE_DEC,     NULL,   0,  "The index within this frame.",          HFILL}},
        { &hf_xplane_flir_out_framecount,   { "Frame Count",    "xplane.flir.framecount",   FT_UINT8, BASE_DEC,     NULL,   0,  "Number of packets to make up an image.",          HFILL}},
        { &hf_xplane_flir_out_imagedata,    { "Image Date",     "xplane.flir.imagedata",    FT_BYTES, BASE_NONE,    NULL,   0,  "The image data. May need to be appended if split other multiple packets.", HFILL}}
    };
    static hf_register_info hf_xplane_ise4[] =
    {
        { &hf_xplane_ise4_header,       { "Header",         "xplane.ise4",              FT_STRINGZ,     STR_ASCII,  NULL,   0,  "ISE4 Header",  HFILL}},
        { &hf_xplane_ise4_machinetype,  { "Machine Type",   "xplane.ise4.machinetype",  FT_INT32,       BASE_DEC,   VALS(vals_ISEx_MachineType),   0,  "The network option for this packet", HFILL}},
        { &hf_xplane_ise4_address,      { "Address",        "xplane.ise4.address",      FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "The address to set.",      HFILL}},
        { &hf_xplane_ise4_port,         { "Port",           "xplane.ise4.port",         FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "The port to set.",         HFILL}},
        { &hf_xplane_ise4_enabled,      { "Enabled",        "xplane.ise4.enabled",      FT_INT32,       BASE_DEC,   NULL,   0,  "Enabled (0=false, 1=true).",      HFILL}}
    };
    static hf_register_info hf_xplane_ise6[] =
    {
        { &hf_xplane_ise6_header,       { "Header",         "xplane.ise6",              FT_STRINGZ,     STR_ASCII,  NULL,   0,  "ISE6 Header",  HFILL}},
        { &hf_xplane_ise6_machinetype,  { "Machine Type",   "xplane.ise6.machinetype",  FT_INT32,       BASE_DEC,   VALS(vals_ISEx_MachineType),   0,  "The network option for this packet", HFILL}},
        { &hf_xplane_ise6_address,      { "Address",        "xplane.ise6.address",      FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "The address to set.",      HFILL}},
        { &hf_xplane_ise6_port,         { "Port",           "xplane.ise6.port",         FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "The port to set.",         HFILL}},
        { &hf_xplane_ise6_enabled,      { "Enabled",        "xplane.ise6.enabled",      FT_INT32,       BASE_DEC,   NULL,   0,  "Enabled (0=false, 1=true).",      HFILL}}
    };
    static hf_register_info hf_xplane_lsnd[] =
    {
        { &hf_xplane_lsnd_header,   { "Header",     "xplane.lsnd",          FT_STRINGZ,     STR_ASCII,  NULL,   0,  "LSND Header",  HFILL}},
        { &hf_xplane_lsnd_index,    { "Index",      "xplane.lsnd.index",    FT_INT32,       BASE_DEC,   NULL,   0,  "Index (0->4)",        HFILL}},
        { &hf_xplane_lsnd_speed,    { "Speed",      "xplane.lsnd.speed",    FT_FLOAT,       BASE_NONE,  NULL,   0,  "Relative Speed (0->1)",        HFILL}},
        { &hf_xplane_lsnd_volume,   { "Volume",     "xplane.lsnd.volume",   FT_FLOAT,       BASE_NONE,  NULL,   0,  "Relative Volume (0->1)",       HFILL}},
        { &hf_xplane_lsnd_filename, { "Filename",   "xplane.lsnd.filename", FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "Relative Filename from the X-Plane home directory. Use Unix-style / seperators.",     HFILL}}
    };
    static hf_register_info hf_xplane_nfal[] =
    {
        { &hf_xplane_nfal_header,       { "Header",         "xplane.nfal",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "NFAL Header",  HFILL}},
        { &hf_xplane_nfal_navaidcode,   { "Navaid Code",    "xplane.nfal.id",   FT_STRINGZ, STR_ASCII,  NULL,   0,  "The NavAid to fail.", HFILL}},
    };
    static hf_register_info hf_xplane_nrec[] =
    {
        { &hf_xplane_nrec_header,       { "Header",         "xplane.nrec",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "NREC Header",  HFILL}},
        { &hf_xplane_nrec_navaidcode,   { "Navaid Code",    "xplane.nrec.id",   FT_STRINGZ, STR_ASCII,  NULL,   0,  "The NavAid to recover.", HFILL}},
    };
    static hf_register_info hf_xplane_objl[] =
    {
        { &hf_xplane_objl_header,       { "Header",     "xplane.objl",              FT_STRINGZ, STR_ASCII,   NULL,   0,  "OBJL Header",  HFILL}},
        { &hf_xplane_objl_index,        { "Index",      "xplane.objl.index",        FT_INT32,   BASE_DEC,    NULL,   0,  "The index assigned to this object (see OBJN).",        HFILL}},
        { &hf_xplane_objl_padding1,     { "Padding",    "xplane.objl.padding1",     FT_BYTES,   BASE_NONE,   NULL,   0,  "4 bytes of padding",    HFILL}},
        { &hf_xplane_objl_latitude,     { "Latitude",   "xplane.objl.latitude",     FT_DOUBLE,  BASE_NONE,   NULL,   0,  "Latitude of the object centre",     HFILL}},
        { &hf_xplane_objl_longitude,    { "Longitude",  "xplane.objl.longitude",    FT_DOUBLE,  BASE_NONE,   NULL,   0,  "Longitude of the object centre",    HFILL}},
        { &hf_xplane_objl_elevation,    { "Elevation",  "xplane.objl.elevation",    FT_DOUBLE,  BASE_NONE,   NULL,   0,  "Elevation of the object centre",    HFILL}},
        { &hf_xplane_objl_psi,          { "Psi",        "xplane.objl.psi",          FT_FLOAT,   BASE_NONE,   NULL,   0,  "True Heading (degrees)",          HFILL}},
        { &hf_xplane_objl_theta,        { "Theta",      "xplane.objl.theta",        FT_FLOAT,   BASE_NONE,   NULL,   0,  "Pitch (Positive = up)",        HFILL}},
        { &hf_xplane_objl_phi,          { "Phi",        "xplane.objl.phi",          FT_FLOAT,   BASE_NONE,   NULL,   0,  "Roll (Positive = right)",          HFILL}},
        { &hf_xplane_objl_onground,     { "Onground ",  "xplane.objl.onground",     FT_INT32,   BASE_DEC,    NULL,   0,  "Onground (0=No, 1=Yes)",     HFILL}},
        { &hf_xplane_objl_smokesize,    { "Smokesize",  "xplane.objl.smokesize",    FT_FLOAT,   BASE_NONE,   NULL,   0,  "Smoke Size",    HFILL}},
        { &hf_xplane_objl_padding2,     { "Padding",    "xplane.objl.padding2",     FT_BYTES,   BASE_NONE,   NULL,   0,  "2 bytes of padding",    HFILL}}
    };
    static hf_register_info hf_xplane_objn[] =
    {
        { &hf_xplane_objn_header,       { "Header",     "xplane.objn",              FT_STRINGZ,     STR_ASCII,  NULL,   0,  "OBJN Header",  HFILL}},
        { &hf_xplane_objn_index,        { "Index",      "xplane.objn.index",        FT_INT32,       BASE_DEC,   NULL,   0,  "Index to assign to this object (See OBJL).",        HFILL}},
        { &hf_xplane_objn_filename,     { "Filename",   "xplane.objn.filename",     FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "OBJ7 filename relative to X-Plane hole folder",     HFILL}},
    };
    static hf_register_info hf_xplane_prel[] =
    {
        { &hf_xplane_prel_header,           { "Header",             "xplane.prel",                  FT_STRINGZ, STR_ASCII,  NULL,   0,  "PREL Header",      HFILL}},
        { &hf_xplane_prel_starttype,        { "Start Type",         "xplane.prel.starttype",        FT_INT32,   BASE_DEC,   VALS(vals_StartType),   0,  "The Start Type to execute.",       HFILL}},
        { &hf_xplane_prel_aircraftindex,    { "Aircraft Index",     "xplane.prel.aircraftindex",    FT_INT32,   BASE_DEC,   NULL,   0,  "Aircraft Index (0=Own Plane, 1->19 = AI Plane).",            HFILL}},
        { &hf_xplane_prel_ICAO,             { "ICAO",               "xplane.prel.ICAO",             FT_STRING,  STR_ASCII,  NULL,   0,  "Airport / NavAid code to place the aircraft at. Note: Max 7 chars as the packet's struct is 8 chars including the ending '\0'.",             HFILL}},
        { &hf_xplane_prel_runwayindex,      { "Runway Index",       "xplane.prel.runwayindex",      FT_INT32,   BASE_DEC,   NULL,   0,  "Runway Index. 0 based on the order listed in the apt.dat file. Note 09L/27R will be one runway. See Runway direction for which end to start from.",HFILL}},
        { &hf_xplane_prel_runwaydirection,  { "Runway Direction",   "xplane.prel.runwaydirection",  FT_INT32,   BASE_DEC,   NULL,   0,  "Runway Direction. 0 (Normal) or 1 (Reversed). So for 09L/27R use 1 for 27R. For a Helipad this reverses the helipad's heading.", HFILL}},
        { &hf_xplane_prel_latitude,         { "Latitude",           "xplane.prel.latitude",         FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Latitude - Ignored if the Start Type is not a LatLong.",         HFILL}},
        { &hf_xplane_prel_longitude,        { "Longitude",          "xplane.prel.longitude",        FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Longitude - Ignored if the Start Type is not a LatLong.",        HFILL}},
        { &hf_xplane_prel_elevation,        { "Elevation",          "xplane.prel.elevation",        FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Elevation (Metres above Mean Sea Level) - Ignored if the Start Type is not a LatLong.",        HFILL}},
        { &hf_xplane_prel_trueheading,      { "True Heading",       "xplane.prel.trueheading",      FT_DOUBLE,  BASE_NONE,  NULL,   0,  "True Heading -  Ignored if the Start Type is not a LatLong.",     HFILL}},
        { &hf_xplane_prel_speed,            { "Speed",              "xplane.prel.speed",            FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Speed (Metres per Second) - Ignored if the Start Type is not a LatLong.",            HFILL}}
    };
    static hf_register_info hf_xplane_quit[] =
    {
        { &hf_xplane_quit_header,   { "Header", "xplane.quit", FT_STRINGZ, STR_ASCII, NULL, 0, "QUIT Header", HFILL}},
    };
    static hf_register_info hf_xplane_radr_in[] =
    {
        { &hf_xplane_radr_in_header,        { "Header",             "xplane.radr",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "RADR Header (in)", HFILL}},
        { &hf_xplane_radr_in_pointcount,    { "Points Per Frame",   "xplane.radr.id",   FT_STRINGZ, STR_ASCII,  NULL,   0,  "The number of points to send per drawn frame", HFILL}},
    };
    static hf_register_info hf_xplane_radr_out[] =
    {
        { &hf_xplane_radr_out_header,        { "Header",        "xplane.radr",                  FT_STRINGZ, STR_ASCII,  NULL,   0,  "RADR Header (out)",    HFILL}},
        { &hf_xplane_radr_out_longitude,     { "Longitude",     "xplane.radr.longitude",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Longitude for this weather point",            HFILL}},
        { &hf_xplane_radr_out_latitude,      { "Latitude",      "xplane.radr.latitude",         FT_FLOAT,   BASE_NONE,  NULL,   0,  "Latitude for this weather point",             HFILL}},
        { &hf_xplane_radr_out_precipitation, { "Precipitation", "xplane.radr.precipitation",    FT_INT8,    BASE_DEC,   NULL,   0,  "Precipitation (0->100)",        HFILL}},
        { &hf_xplane_radr_out_height,        { "Storm Height",  "xplane.radr.height",           FT_FLOAT,   BASE_NONE,  NULL,   0,  "Storm top (metres above sea level",               HFILL}},
    };
    static hf_register_info hf_xplane_reco[] =
    {
        { &hf_xplane_reco_header,   { "Header", "xplane.reco",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "RECO Header",  HFILL}},
        { &hf_xplane_reco_id,       { "Id",     "xplane.reco.id",   FT_STRINGZ, STR_ASCII,  NULL,   0,  "Id of the plane system to recover",           HFILL}}
    };
    static hf_register_info hf_xplane_rese[] =
    {
        { &hf_xplane_rese_header,   { "Header", "xplane.rese",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "RESE Header",  HFILL}},
    };
    static hf_register_info hf_xplane_rpos_in[] =
    {
        { &hf_xplane_rpos_in_header,        { "Header",     "xplane.rpos",              FT_STRINGZ, STR_ASCII,  NULL,   0,  "RPOS Header (in)",  HFILL}},
        { &hf_xplane_rpos_in_frequency,     { "Frequency",  "xplane.rpos.frequency",    FT_STRINGZ, STR_ASCII,  NULL,   0,  "Frequency the RPOS will be emitted by X-Plane. 0 to stop.",  HFILL}},
    };
    static hf_register_info hf_xplane_rpos_out[] =
    {
        { &hf_xplane_rpos_out_header,       { "Header",     "xplane.rpos",              FT_STRING,   STR_ASCII,  NULL,   0,  "RPOS Header (out)",                       HFILL}},
        { &hf_xplane_rpos_out_longitude,    { "Longitude",  "xplane.rpos.longitude",    FT_DOUBLE,   BASE_NONE,  NULL,   0,  "Plane's Longitude",                               HFILL}},
        { &hf_xplane_rpos_out_latitude ,    { "Latitude",   "xplane.rpos.latitude",     FT_DOUBLE,   BASE_NONE,  NULL,   0,  "Plane's Latitude",                               HFILL}},
        { &hf_xplane_rpos_out_elevation,    { "Elevation",  "xplane.rpos.elevation",    FT_DOUBLE,   BASE_NONE,  NULL,   0,  "Plane's Altitude (metres above mean sea level)",  HFILL}},
        { &hf_xplane_rpos_out_height,       { "Height",     "xplane.rpos.height",       FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Height (metres above ground)",            HFILL}},
        { &hf_xplane_rpos_out_theta,        { "Theta",      "xplane.rpos.theta",        FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Pitch (degrees)",                         HFILL}},
        { &hf_xplane_rpos_out_psi,          { "Psi",        "xplane.rpos.psi",          FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's True Heading (degrees)",                  HFILL}},
        { &hf_xplane_rpos_out_phi,          { "Phi",        "xplane.rpos.phi",          FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Roll (degrees)",                          HFILL}},
        { &hf_xplane_rpos_out_vx,           { "Vx",         "xplane.rpos.vx",           FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Velocity (East)",                         HFILL}},
        { &hf_xplane_rpos_out_vy,           { "Vy",         "xplane.rpos.vy",           FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Velocity (Vertical)",                     HFILL}},
        { &hf_xplane_rpos_out_vz,           { "Vz",         "xplane.rpos.vz",           FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Velocity (South)",                        HFILL}},
        { &hf_xplane_rpos_out_rollrate,     { "Rollrate",   "xplane.rpos.rollrate",     FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Roll Rate",                               HFILL}},
        { &hf_xplane_rpos_out_pitchrate,    { "Pitchrate",  "xplane.rpos.pitchrate",    FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Pitch Rate",                              HFILL}},
        { &hf_xplane_rpos_out_yawrate,      { "Yawrate",    "xplane.rpos.yawrate",      FT_FLOAT,    BASE_NONE,  NULL,   0,  "Plane's Yaw Rate",                                HFILL}}
    };
    static hf_register_info hf_xplane_rref_in[] =
    {
        { &hf_xplane_rref_in_header,    { "Header",     "xplane.rref",              FT_STRINGZ,     STR_ASCII,  NULL,   0,  "RREF Header (IN)", HFILL}},
        { &hf_xplane_rref_in_frequency, { "Frequency",  "xplane.rref.frequency",    FT_INT32,       BASE_DEC,   NULL,   0,  "Frequency. 0 to stop.",        HFILL}},
        { &hf_xplane_rref_in_id,        { "Id",         "xplane.rref.id",           FT_INT32,       BASE_DEC,   NULL,   0,  "Id to use for this dataref.",               HFILL}},
        { &hf_xplane_rref_in_dataref,   { "Dataref",    "xplane.rref.dataref",      FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "The Dataref. Padded with '\0'.",          HFILL}}
    };
    static hf_register_info hf_xplane_rref_out[] =
    {
        { &hf_xplane_rref_out_header,   { "Header", "xplane.rref",          FT_STRINGZ, STR_ASCII,  NULL,   0,  "RREF Header (OUT)",    HFILL}},
        { &hf_xplane_rref_out_id,       { "Id",     "xplane.rref.id",       FT_INT32,   BASE_DEC,   NULL,   0,  "Id for this dataref.",                   HFILL}},
        { &hf_xplane_rref_out_value,    { "Value",  "xplane.rref.value",    FT_FLOAT,   BASE_NONE,  NULL,   0,  "Value for this dataref.",                HFILL}}
    };
    static hf_register_info hf_xplane_shut[] =
    {
        { &hf_xplane_shut_header,   { "Header", "xplane.shut",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "SHUT Header",  HFILL}},
    };
    static hf_register_info hf_xplane_simo[] =
    {
        { &hf_xplane_simo_header,   { "Header", "xplane.simo",          FT_STRINGZ,     STR_ASCII,  NULL,   0,  "SIMO Header",  HFILL}},
        { &hf_xplane_simo_action,   { "Header", "xplane.simo.action",   FT_INT32,       BASE_DEC,   NULL,   0,  "Action to take",       HFILL}},
        { &hf_xplane_simo_filename, { "Header", "xplane.simo.filename", FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "Filename relative to X-Plane home folder.",     HFILL}}
    };
    static hf_register_info hf_xplane_soun[] =
    {
        { &hf_xplane_soun_header,   { "Header",     "xplane.soun",          FT_STRINGZ,     STR_ASCII,  NULL,   0,  "SOUN Header",  HFILL}},
        { &hf_xplane_soun_speed,    { "Speed",      "xplane.soun.speed",    FT_FLOAT,       BASE_NONE,  NULL,   0,  "Relative Speed (0->1)",        HFILL}},
        { &hf_xplane_soun_volume,   { "Volume",     "xplane.soun.volume",   FT_FLOAT,       BASE_NONE,  NULL,   0,  "Relative Volume (0->1)",       HFILL}},
        { &hf_xplane_soun_filename, { "Filename",   "xplane.soun.filename", FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "Relative Filename from the X-Plane home directory. Use Unix-style / seperators.",     HFILL}}
    };
    static hf_register_info hf_xplane_ssnd[] =
    {
        { &hf_xplane_ssnd_header,   { "Header",     "xplane.ssnd",          FT_STRINGZ,     STR_ASCII,  NULL,   0,  "SSND Header",  HFILL}},
        { &hf_xplane_ssnd_index,    { "Index",      "xplane.ssnd.index",    FT_INT32,       BASE_DEC,   NULL,   0,  "Index (0->4)",        HFILL}},
        { &hf_xplane_ssnd_speed,    { "Speed",      "xplane.ssnd.speed",    FT_FLOAT,       BASE_NONE,  NULL,   0,  "Relative Speed (0->1)",        HFILL}},
        { &hf_xplane_ssnd_volume,   { "Volume",     "xplane.ssnd.volume",   FT_FLOAT,       BASE_NONE,  NULL,   0,  "Relative Volume (0->1)",       HFILL}},
        { &hf_xplane_ssnd_filename, { "Filename",   "xplane.ssnd.filename", FT_STRINGZPAD,  STR_ASCII,  NULL,   0,  "Relative Filename from the X-Plane home directory. Use Unix-style / seperators.",     HFILL}}
    };
    static hf_register_info hf_xplane_ucoc[] =
    {
        { &hf_xplane_ucoc_header,   { "Header", "xplane.ucoc",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "UCOC Header",  HFILL}},
        { &hf_xplane_ucoc_id,       { "Id",     "xplane.ucoc.id",   FT_INT32,   BASE_DEC,   NULL,   0,  "A Data row id",      HFILL}}
    };
    static hf_register_info hf_xplane_usel[] =
    {
        { &hf_xplane_usel_header,   { "Header", "xplane.usel",      FT_STRINGZ, STR_ASCII,  NULL,   0,  "USEL Header",  HFILL}},
        { &hf_xplane_usel_id,       { "Id",     "xplane.usel.id",   FT_INT32,   BASE_DEC,   NULL,   0,  "A Data row id",      HFILL}}
    };
    static hf_register_info hf_xplane_vehx[] =
    {
        { &hf_xplane_vehx_header,       { "Header",     "xplane.vehx",              FT_STRINGZ, STR_ASCII,  NULL,   0,  "VEHX Header",  HFILL}},
        { &hf_xplane_vehx_id,           { "Id",         "xplane.vehx.id",           FT_INT32,   BASE_DEC,   NULL,   0,  "Aircraft Index (0=Own Plane, 1->19 = AI Plane).",            HFILL}},
        { &hf_xplane_vehx_latitude,     { "Latitude",   "xplane.vehx.latitude",     FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Aircraft Latitude",     HFILL}},
        { &hf_xplane_vehx_longitude,    { "Longitude",  "xplane.vehx.longitude",    FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Aircraft Longitude",    HFILL}},
        { &hf_xplane_vehx_elevation,    { "Elevation",  "xplane.vehx.elevation",    FT_DOUBLE,  BASE_NONE,  NULL,   0,  "Aircraft Elevation",    HFILL}},
        { &hf_xplane_vehx_heading,      { "Heading",    "xplane.vehx.heading",      FT_FLOAT,   BASE_NONE,  NULL,   0,  "Aircraft Heading (degrees)",      HFILL}},
        { &hf_xplane_vehx_pitch,        { "Pitch",      "xplane.vehx.pitch",        FT_FLOAT,   BASE_NONE,  NULL,   0,  "Aircraft Pitch (degrees, positive=up)",        HFILL}},
        { &hf_xplane_vehx_roll,         { "Roll",       "xplane.vehx.roll",         FT_FLOAT,   BASE_NONE,  NULL,   0,  "Aircraft Roll (degrees, positive=right)",         HFILL}}
    };

    static gint* ett[] =
    {
        &ett_xplane_acfn,
        &ett_xplane_acpr,
        &ett_xplane_alrt,
        &ett_xplane_becn,
        &ett_xplane_cmnd,
        &ett_xplane_data,
        &ett_xplane_dcoc,
        &ett_xplane_dref,
        &ett_xplane_dsel,
        &ett_xplane_fail,
        &ett_xplane_flir_in,
        &ett_xplane_flir_out,
        &ett_xplane_ise4,
        &ett_xplane_ise6,
        &ett_xplane_lsnd,
        &ett_xplane_nfal,
        &ett_xplane_nrec,
        &ett_xplane_objl,
        &ett_xplane_objn,
        &ett_xplane_prel,
        &ett_xplane_quit,
        &ett_xplane_radr_in,
        &ett_xplane_radr_out,
        &ett_xplane_reco,
        &ett_xplane_rese,
        &ett_xplane_rpos_in,
        &ett_xplane_rpos_out,
        &ett_xplane_rref_in,
        &ett_xplane_rref_out,
        &ett_xplane_shut,
        &ett_xplane_simo,
        &ett_xplane_soun,
        &ett_xplane_ssnd,
        &ett_xplane_ucoc,
        &ett_xplane_usel,
        &ett_xplane_vehx
    };

    proto_xplane = proto_register_protocol("X-Plane", "XPLANE", "xplane");

    proto_register_subtree_array(ett, array_length(ett));

    proto_register_field_array(proto_xplane, hf_xplane_acfn, array_length(hf_xplane_acfn));
    proto_register_field_array(proto_xplane, hf_xplane_acpr, array_length(hf_xplane_acpr));
    proto_register_field_array(proto_xplane, hf_xplane_alrt, array_length(hf_xplane_alrt));
    proto_register_field_array(proto_xplane, hf_xplane_becn, array_length(hf_xplane_becn));
    proto_register_field_array(proto_xplane, hf_xplane_cmnd, array_length(hf_xplane_cmnd));
    proto_register_field_array(proto_xplane, hf_xplane_data, array_length(hf_xplane_data));
    proto_register_field_array(proto_xplane, hf_xplane_dcoc, array_length(hf_xplane_dcoc));
    proto_register_field_array(proto_xplane, hf_xplane_dref, array_length(hf_xplane_dref));
    proto_register_field_array(proto_xplane, hf_xplane_dsel, array_length(hf_xplane_dsel));
    proto_register_field_array(proto_xplane, hf_xplane_fail, array_length(hf_xplane_fail));
    proto_register_field_array(proto_xplane, hf_xplane_flir_in, array_length(hf_xplane_flir_in));
    proto_register_field_array(proto_xplane, hf_xplane_flir_out, array_length(hf_xplane_flir_out));
    proto_register_field_array(proto_xplane, hf_xplane_ise4, array_length(hf_xplane_ise4));
    proto_register_field_array(proto_xplane, hf_xplane_ise6, array_length(hf_xplane_ise6));
    proto_register_field_array(proto_xplane, hf_xplane_lsnd, array_length(hf_xplane_lsnd));
    proto_register_field_array(proto_xplane, hf_xplane_nfal, array_length(hf_xplane_nfal));
    proto_register_field_array(proto_xplane, hf_xplane_nrec, array_length(hf_xplane_nrec));
    proto_register_field_array(proto_xplane, hf_xplane_objl, array_length(hf_xplane_objl));
    proto_register_field_array(proto_xplane, hf_xplane_objn, array_length(hf_xplane_objn));
    proto_register_field_array(proto_xplane, hf_xplane_prel, array_length(hf_xplane_prel));
    proto_register_field_array(proto_xplane, hf_xplane_quit, array_length(hf_xplane_quit));
    proto_register_field_array(proto_xplane, hf_xplane_radr_in, array_length(hf_xplane_radr_in));
    proto_register_field_array(proto_xplane, hf_xplane_radr_out, array_length(hf_xplane_radr_out));
    proto_register_field_array(proto_xplane, hf_xplane_reco, array_length(hf_xplane_reco));
    proto_register_field_array(proto_xplane, hf_xplane_rese, array_length(hf_xplane_rese));
    proto_register_field_array(proto_xplane, hf_xplane_rpos_in, array_length(hf_xplane_rpos_in));
    proto_register_field_array(proto_xplane, hf_xplane_rpos_out, array_length(hf_xplane_rpos_out));
    proto_register_field_array(proto_xplane, hf_xplane_rref_in, array_length(hf_xplane_rref_in));
    proto_register_field_array(proto_xplane, hf_xplane_rref_out, array_length(hf_xplane_rref_out));
    proto_register_field_array(proto_xplane, hf_xplane_shut, array_length(hf_xplane_shut));
    proto_register_field_array(proto_xplane, hf_xplane_simo, array_length(hf_xplane_simo));
    proto_register_field_array(proto_xplane, hf_xplane_soun, array_length(hf_xplane_soun));
    proto_register_field_array(proto_xplane, hf_xplane_ssnd, array_length(hf_xplane_ssnd));
    proto_register_field_array(proto_xplane, hf_xplane_ucoc, array_length(hf_xplane_ucoc));
    proto_register_field_array(proto_xplane, hf_xplane_usel, array_length(hf_xplane_usel));
    proto_register_field_array(proto_xplane, hf_xplane_vehx, array_length(hf_xplane_vehx));

    module_t* xplane_udp_prefs_module = prefs_register_protocol(proto_xplane, proto_reg_handoff_xplane);
    prefs_register_uint_preference(xplane_udp_prefs_module, "listenerport", "X-Plane UDP Listener Port", "The Port to listen on for X-Plane packets if other than the default", 10, &xplane_pref_udp_port);
    prefs_register_uint_preference(xplane_udp_prefs_module, "beaconport", "X-Plane UDP Beacon Port", "The Port to listen on for BECN packet if other than the default", 10, &xplane_pref_becn_port);
}

void proto_reg_handoff_xplane(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t xplane_becn_handle;
    static dissector_handle_t xplane_udp_handle;
    static int current_becn_port;
    static int current_udp_port;

    if (!initialized)
    {
        xplane_udp_handle = create_dissector_handle(dissect_xplane, proto_xplane);
        initialized = TRUE;
    }
    else
    {
        dissector_delete_uint("udp.port", current_becn_port, xplane_becn_handle);
        dissector_delete_uint("udp.port", current_udp_port, xplane_udp_handle);
    }

    current_udp_port = xplane_pref_udp_port;
    current_becn_port = xplane_pref_becn_port;

    dissector_add_uint("udp.port", current_udp_port, xplane_udp_handle);
    dissector_add_uint("udp.port", current_becn_port, xplane_udp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
