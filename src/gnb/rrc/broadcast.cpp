//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <gnb/ngap/task.hpp>
#include <lib/asn/rrc.hpp>
#include <lib/asn/utils.hpp>
#include <lib/rrc/encode.hpp>
#include <utils/common.hpp>

#include <asn/rrc/ASN_RRC_MIB.h>
#include <asn/rrc/ASN_RRC_PLMN-IdentityInfo.h>
#include <asn/rrc/ASN_RRC_PLMN-IdentityInfoList.h>
#include <asn/rrc/ASN_RRC_SIB1-vExt-IEs.h>
#include <asn/rrc/ASN_RRC_SIB1.h>
#include <asn/rrc/ASN_RRC_UAC-BarringInfoSet.h>
#include <asn/rrc/ASN_RRC_UAC-BarringInfoSetIndex.h>
#include <asn/rrc/ASN_RRC_UAC-BarringPerCat.h>
#include <asn/rrc/ASN_RRC_UAC-BarringPerCatList.h>

extern "C"
{
#include "ext/compact25519/c25519/edsign.h"
}

namespace nr::gnb
{

static ASN_RRC_BCCH_BCH_Message *ConstructMibMessage(bool barred, bool intraFreqReselectAllowed)
{
    auto *pdu = asn::New<ASN_RRC_BCCH_BCH_Message>();
    pdu->message.present = ASN_RRC_BCCH_BCH_MessageType_PR_mib;
    pdu->message.choice.mib = asn::New<ASN_RRC_MIB>();

    auto &mib = *pdu->message.choice.mib;

    asn::SetBitStringInt<6>(0, mib.systemFrameNumber);
    mib.subCarrierSpacingCommon = ASN_RRC_MIB__subCarrierSpacingCommon_scs15or60;
    mib.ssb_SubcarrierOffset = 0;
    mib.dmrs_TypeA_Position = ASN_RRC_MIB__dmrs_TypeA_Position_pos2;
    mib.cellBarred = barred ? ASN_RRC_MIB__cellBarred_barred : ASN_RRC_MIB__cellBarred_notBarred;
    mib.intraFreqReselection = intraFreqReselectAllowed ? ASN_RRC_MIB__intraFreqReselection_allowed
                                                        : ASN_RRC_MIB__intraFreqReselection_notAllowed;
    asn::SetBitStringInt<1>(0, mib.spare);
    mib.pdcch_ConfigSIB1.controlResourceSetZero = 0;
    mib.pdcch_ConfigSIB1.searchSpaceZero = 0;
    return pdu;
}

static ASN_RRC_BCCH_DL_SCH_Message *ConstructSib1Message(bool cellReserved, int tac, int64_t nci, const Plmn &plmn,
                                                         const UacAiBarringSet &aiBarringSet)
{
    auto *pdu = asn::New<ASN_RRC_BCCH_DL_SCH_Message>();
    pdu->message.present = ASN_RRC_BCCH_DL_SCH_MessageType_PR_c1;
    pdu->message.choice.c1 = asn::NewFor(pdu->message.choice.c1);
    pdu->message.choice.c1->present = ASN_RRC_BCCH_DL_SCH_MessageType__c1_PR_systemInformationBlockType1;
    pdu->message.choice.c1->choice.systemInformationBlockType1 = asn::New<ASN_RRC_SIB1>();

    auto &sib1 = *pdu->message.choice.c1->choice.systemInformationBlockType1;

    if (cellReserved)
    {
        asn::MakeNew(sib1.cellAccessRelatedInfo.cellReservedForOtherUse);
        *sib1.cellAccessRelatedInfo.cellReservedForOtherUse =
            ASN_RRC_CellAccessRelatedInfo__cellReservedForOtherUse_true;
    }

    auto *plmnInfo = asn::New<ASN_RRC_PLMN_IdentityInfo>();
    plmnInfo->cellReservedForOperatorUse = cellReserved
                                               ? ASN_RRC_PLMN_IdentityInfo__cellReservedForOperatorUse_reserved
                                               : ASN_RRC_PLMN_IdentityInfo__cellReservedForOperatorUse_notReserved;
    asn::MakeNew(plmnInfo->trackingAreaCode);
    asn::SetBitStringInt<24>(tac, *plmnInfo->trackingAreaCode);
    asn::SetBitStringLong<36>(nci, plmnInfo->cellIdentity);
    asn::SequenceAdd(plmnInfo->plmn_IdentityList, asn::rrc::NewPlmnId(plmn));
    asn::SequenceAdd(sib1.cellAccessRelatedInfo.plmn_IdentityList, plmnInfo);

    asn::MakeNew(sib1.uac_BarringInfo);

    auto *info = asn::New<ASN_RRC_UAC_BarringInfoSet>();
    info->uac_BarringFactor = ASN_RRC_UAC_BarringInfoSet__uac_BarringFactor_p50;
    info->uac_BarringTime = ASN_RRC_UAC_BarringInfoSet__uac_BarringTime_s4;

    asn::SetBitStringInt<7>(bits::Consequential8(false, aiBarringSet.ai1, aiBarringSet.ai2, aiBarringSet.ai11,
                                                 aiBarringSet.ai12, aiBarringSet.ai13, aiBarringSet.ai14,
                                                 aiBarringSet.ai15),
                            info->uac_BarringForAccessIdentity);

    asn::SequenceAdd(sib1.uac_BarringInfo->uac_BarringInfoSetList, info);

    asn::MakeNew(sib1.uac_BarringInfo->uac_BarringForCommon);

    for (size_t i = 0; i < 63; i++)
    {
        auto *item = asn::New<ASN_RRC_UAC_BarringPerCat>();
        item->accessCategory = static_cast<decltype(item->accessCategory)>(i + 1);
        item->uac_barringInfoSetIndex = 1;

        asn::SequenceAdd(*sib1.uac_BarringInfo->uac_BarringForCommon, item);
    }

    return pdu;
}

void GnbRrcTask::onBroadcastTimerExpired()
{
    triggerSysInfoBroadcast();
}

void GnbRrcTask::triggerSysInfoBroadcast()
{
    auto *mib = ConstructMibMessage(m_isBarred, m_intraFreqReselectAllowed);
    auto *sib1 = ConstructSib1Message(m_cellReserved, m_config->tac, m_config->nci, m_config->plmn, m_aiBarringSet);

    //! 서명 생성 및 삽입 ######################
    // (A) 서명용 코어 인코딩
    OctetString mib_bytes = rrc::encode::EncodeS(asn_DEF_ASN_RRC_BCCH_BCH_Message, mib);
    OctetString sib1_core = rrc::encode::EncodeS(asn_DEF_ASN_RRC_BCCH_DL_SCH_Message, sib1);

    // (B) TS 만들고 서명
    // 8바이트 big-endian timestamp: utils::CurrentTimeStamp() 사용
    uint64_t ts_val = (uint64_t)utils::CurrentTimeStamp().ntpValue(); // 64비트 NTP 타임
    uint8_t ts_be[8];
    for (int i = 0; i < 8; i++)
    {
        ts_be[7 - i] = (ts_val >> (i * 8)) & 0xFF;
    }

    // msg = APER(MIB) || APER(SIB1_core) || TS(8B)
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), mib_bytes.data(), mib_bytes.data() + mib_bytes.length());
    msg.insert(msg.end(), sib1_core.data(), sib1_core.data() + sib1_core.length());
    msg.insert(msg.end(), ts_be, ts_be + 8);

    // edsign 서명
    // gNB 시크릿키 (32B)
    static const uint8_t GNB_SECRET[32] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22,
                                           0x22, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                                           0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    // gNB 공개키(32B)
    static const uint8_t GNB_PUB[32] = {0x64, 0xE7, 0x78, 0x2E, 0x29, 0xF2, 0x21, 0x99, 0x99, 0x66, 0x4E,
                                        0x16, 0x3F, 0xD6, 0xAD, 0xBB, 0x80, 0xCF, 0xBA, 0xE5, 0xAD, 0x86,
                                        0xA2, 0x85, 0xA3, 0x86, 0x40, 0x5A, 0x70, 0x20, 0x10, 0x61};
    uint8_t sig[64];
    edsign_sign(sig, GNB_PUB, GNB_SECRET, msg.data(), msg.size());

    // (C) SIB1에 주입 (이제 구조체 상태가 “최종”)
    auto &sib1_ie = *sib1->message.choice.c1->choice.systemInformationBlockType1;
    asn::MakeNew(sib1_ie.nonCriticalExtension);
    OctetString ts_os(std::vector<uint8_t>(ts_be, ts_be + sizeof(ts_be)));
    asn::SetOctetString(sib1_ie.nonCriticalExtension->timestampBE, ts_os);
    OctetString sig_os(std::vector<uint8_t>(sig, sig + sizeof(sig)));
    asn::SetOctetString(sib1_ie.nonCriticalExtension->signature, sig_os);
    //! ###########################################

    sendRrcMessage(mib);
    sendRrcMessage(sib1);

    asn::Free(asn_DEF_ASN_RRC_BCCH_BCH_Message, mib);
    asn::Free(asn_DEF_ASN_RRC_BCCH_DL_SCH_Message, sib1);
}

} // namespace nr::gnb