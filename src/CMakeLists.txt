#********************************************************************
#        _       _         _
#  _ __ | |_  _ | |  __ _ | |__   ___
# | '__|| __|(_)| | / _` || '_ \ / __|
# | |   | |_  _ | || (_| || |_) |\__ \
# |_|    \__|(_)|_| \__,_||_.__/ |___/
#
# www.rt-labs.com
# Copyright 2018 rt-labs AB, Sweden.
#
# This software is dual-licensed under GPLv3 and a commercial
# license. See the file LICENSE.md distributed with this software for
# full license information.
#*******************************************************************/

#cmake_policy(SET CMP0076 NEW)

# NOTE: add headers to make them show up in an IDE
# NOTE: Use full path for the <$<BOOL:${PNET_OPTION_SNMP}> expression
#       to work with certain cmake versions
target_sources (profinet PRIVATE
  ${PROFINET_SOURCE_DIR}/include/pnet_api.h
  ${PROFINET_SOURCE_DIR}/src/pf_includes.h
  ${PROFINET_SOURCE_DIR}/src/pf_types.h
  ${PROFINET_SOURCE_DIR}/src/device/pnet_api.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_block_reader.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_block_writer.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_fspm.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_diag.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmdev.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmdmc.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmina.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmio.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmpbe.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrdr.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrpc.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrpc_epm.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrpc_helpers.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrs.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmsm.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmsu.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmwrr.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_pdport.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_port.c
  ${PROFINET_SOURCE_DIR}/src/device/pf_block_reader.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_block_writer.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_fspm.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_diag.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmdev.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmdmc.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmina.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmio.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmpbe.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrdr.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrpc.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrpc_epm.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrpc_helpers.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmrs.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmsm.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmsu.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_cmwrr.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_pdport.h
  ${PROFINET_SOURCE_DIR}/src/device/pf_port.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_alarm.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_bg_worker.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_cpm.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_dcp.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_ppm.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_ptcp.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_scheduler.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_eth.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_file.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_lldp.c
  $<$<BOOL:${PNET_OPTION_SNMP}>:${PROFINET_SOURCE_DIR}/src/common/pf_snmp.c>
  ${PROFINET_SOURCE_DIR}/src/common/pf_udp.c
  ${PROFINET_SOURCE_DIR}/src/common/pf_alarm.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_bg_worker.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_cpm.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_dcp.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_file.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_ppm.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_ptcp.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_scheduler.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_eth.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_lldp.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_snmp.h
  ${PROFINET_SOURCE_DIR}/src/common/pf_udp.h
  )
