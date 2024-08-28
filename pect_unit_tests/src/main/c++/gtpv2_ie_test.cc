
// Includes
#include <iostream>
#include "cute.h"
#include "GTPv1_packetFields.h"
#include "gtpv1_utils.h"
#include "gtp_ie_gtpv2.h"
#include "Information_Elements_GTPv2.h"
#include "gtp_ie.h"

//#include <pcap.h>

// Ignore the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"
using std::cout;
using std::endl;


/* parseIMSI_IMEI_Field no longer used
void testParseIMSI_IMEIFields() {
    unsigned char bytes[] = {
            0,
            0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0x76
    };
    ASSERTM("failed on input 1234567891234567 in parse imsi/imei", parseIMSI_IMEI_Field(bytes,0) == 1234567891234567L);
    unsigned char bytes1[] = {
                0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
        };
    ASSERTM("failed on input 0x10^15 in parse imsi/imei", parseIMSI_IMEI_Field(bytes1,0) == 0L);
    unsigned char bytes2[] = {
                0,
                0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99
    };
    ASSERTM("failed on input of all 9s in parse imsi/imei", parseIMSI_IMEI_Field(bytes2,0) == 9999999999999999L);
}
*/

void TestUserLocationInformationStruct() {
    /*   type   len1  len2   spare/ins  SAI etc flags    */
    unsigned char a[5] = { 0x56, 0x12, 0x34,    0x06,      0x1};
    UserLocationInformation *mapPtr = (UserLocationInformation *) a;
    ASSERTM("ULI info test of type field failed at a ", mapPtr->type == 86);
    ASSERTM("ULI info test of length field failed at a", mapPtr->length == 0x3412);
    ASSERTM("ULI info test of instance field failed at a", mapPtr->instance == 6);
    ASSERTM("ULI info test of CGI flag failed at a ", mapPtr->CellGlobalIdentiferFlag == 1);
    ASSERTM("ULI info test of SAI flag failed at a ", mapPtr->ServiceAreaIdentiferFlag == 0);
    ASSERTM("ULI info test of RAI flag failed at a ", mapPtr->RoutingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of TAI flag failed at a ", mapPtr->TrackingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of ECGI flag failed at a ", mapPtr->E_UTRANCellGlobalIdentifierFlag == 0);
    ASSERTM("ULI info test of LAI flag failed at a ", mapPtr->LocationAreaIdentifierFlag == 0);
    /*   type   len1  len2   spare/ins  SAI etc flags    */
    unsigned char b[5] = { 0x56, 0x12, 0x34,    0x06,      0x2};
    UserLocationInformation *mapPtr2 = (UserLocationInformation *) b;
    ASSERTM("ULI info test of type field failed at b ", mapPtr2->type == 86);
    ASSERTM("ULI info test of length field failed at b", mapPtr2->length == 0x3412);
    ASSERTM("ULI info test of instance field failed at b", mapPtr2->instance == 6);
    ASSERTM("ULI info test of CGI flag failed at b ", mapPtr2->CellGlobalIdentiferFlag == 0);
    ASSERTM("ULI info test of SAI flag failed at b ", mapPtr2->ServiceAreaIdentiferFlag == 1);
    ASSERTM("ULI info test of RAI flag failed at b ", mapPtr->RoutingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of TAI flag failed at b ", mapPtr->TrackingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of ECGI flag failed at b ", mapPtr->E_UTRANCellGlobalIdentifierFlag == 0);
    ASSERTM("ULI info test of LAI flag failed at b ", mapPtr->LocationAreaIdentifierFlag == 0);
    /*   type   len1  len2   spare/ins  SAI etc flags    */
    unsigned char c[5] = { 0x56, 0x12, 0x34,    0x06,      0x04};
    UserLocationInformation *mapPtr3 = (UserLocationInformation *) c;
    ASSERTM("ULI info test of type field failed at c ", mapPtr3->type == 86);
    ASSERTM("ULI info test of length field failed at c", mapPtr3->length == 0x3412);
    ASSERTM("ULI info test of instance field failed at c", mapPtr3->instance == 6);
    ASSERTM("ULI info test of CGI flag failed at c ", mapPtr3->CellGlobalIdentiferFlag == 0);
    ASSERTM("ULI info test of SAI flag failed at c ", mapPtr3->ServiceAreaIdentiferFlag == 0);
    ASSERTM("ULI info test of RAI flag failed at c ", mapPtr3->RoutingAreaIdentityFlag == 1);
    ASSERTM("ULI info test of TAI flag failed at c ", mapPtr3->TrackingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of ECGI flag failed at c ", mapPtr3->E_UTRANCellGlobalIdentifierFlag == 0);
    ASSERTM("ULI info test of LAI flag failed at c ", mapPtr3->LocationAreaIdentifierFlag == 0);
    /*   type   len1  len2   spare/ins  SAI etc flags    */
    unsigned char d[5] = { 0x56, 0x12, 0x34,    0x06,      0x08};
    UserLocationInformation *mapPtr4 = (UserLocationInformation *) d;
    ASSERTM("ULI info test of type field failed at d ", mapPtr4->type == 86);
    ASSERTM("ULI info test of length field failed at d", mapPtr4->length == 0x3412);
    ASSERTM("ULI info test of instance field failed at d", mapPtr4->instance == 6);
    ASSERTM("ULI info test of CGI flag failed at d ", mapPtr4->CellGlobalIdentiferFlag == 0);
    ASSERTM("ULI info test of SAI flag failed at d ", mapPtr4->ServiceAreaIdentiferFlag == 0);
    ASSERTM("ULI info test of RAI flag failed at d ", mapPtr4->RoutingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of TAI flag failed at d ", mapPtr4->TrackingAreaIdentityFlag == 1);
    ASSERTM("ULI info test of ECGI flag failed at d ", mapPtr4->E_UTRANCellGlobalIdentifierFlag == 0);
    ASSERTM("ULI info test of LAI flag failed at d ", mapPtr4->LocationAreaIdentifierFlag == 0);
    /*   type   len1  len2   spare/ins  SAI etc flags    */
    unsigned char e[5] = { 0x56, 0x12, 0x34,    0x06,      0x10};
    UserLocationInformation *mapPtr5 = (UserLocationInformation *) e;
    ASSERTM("ULI info test of type field failed at e ", mapPtr5->type == 86);
    ASSERTM("ULI info test of length field failed at e ", mapPtr5->length == 0x3412);
    ASSERTM("ULI info test of instance field failed at e ", mapPtr5->instance == 6);
    ASSERTM("ULI info test of CGI flag failed at e  ", mapPtr5->CellGlobalIdentiferFlag == 0);
    ASSERTM("ULI info test of SAI flag failed at e  ", mapPtr5->ServiceAreaIdentiferFlag == 0);
    ASSERTM("ULI info test of RAI flag failed at e  ", mapPtr5->RoutingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of TAI flag failed at e  ", mapPtr5->TrackingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of ECGI flag failed at e  ", mapPtr5->E_UTRANCellGlobalIdentifierFlag == 1);
    ASSERTM("ULI info test of LAI flag failed at e  ", mapPtr5->LocationAreaIdentifierFlag == 0);
    /*   type   len1  len2   spare/ins  SAI etc flags    */
    unsigned char f[5] = { 0x56, 0x12, 0x34,    0x06,      0x20};
    UserLocationInformation *mapPtr6 = (UserLocationInformation *) f;
    ASSERTM("ULI info test of type field failed at f ", mapPtr6->type == 86);
    ASSERTM("ULI info test of length field failed at f", mapPtr6->length == 0x3412);
    ASSERTM("ULI info test of instance field failed at f", mapPtr6->instance == 6);
    ASSERTM("ULI info test of CGI flag failed at f ", mapPtr6->CellGlobalIdentiferFlag == 0);
    ASSERTM("ULI info test of SAI flag failed at f ", mapPtr6->ServiceAreaIdentiferFlag == 0);
    ASSERTM("ULI info test of RAI flag failed at f ", mapPtr6->RoutingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of TAI flag failed at f ", mapPtr6->TrackingAreaIdentityFlag == 0);
    ASSERTM("ULI info test of ECGI flag failed at f", mapPtr6->E_UTRANCellGlobalIdentifierFlag == 0);
    ASSERTM("ULI info test of LAI flag failed at f ", mapPtr6->LocationAreaIdentifierFlag == 1);
}

void TestIndicationStruct() {
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char a[] = { 0x4D,     0x12, 0x34,    0x06,       0x01    ,   0x01     ,   0x01     ,   0x01    };
    INDICATION_IE  *mapPtr = (INDICATION_IE *) a;
    ASSERTM("Indication data info test of type field failed at a ", mapPtr->type == 77);
    ASSERTM("Indication data info test of length field failed at a", mapPtr->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at a", mapPtr->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at a", mapPtr->SGWChangeIndication == 1);
    ASSERTM("Indication data info test of ISRAI flag failed at a", mapPtr->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at a", mapPtr->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at a", mapPtr->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at a", mapPtr->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at a", mapPtr->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at a", mapPtr->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at a", mapPtr->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at a", mapPtr->MSValidated == 1);
    ASSERTM("Indication data info test of SI flag failed at a", mapPtr->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at a", mapPtr->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at a", mapPtr->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at a", mapPtr->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at a", mapPtr->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at a", mapPtr->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at a", mapPtr->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at a", mapPtr->CSGChangeReportingSupportIndication == 1);
    ASSERTM("Indication data info test of ISRAU flag failed at a", mapPtr->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at a", mapPtr->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at a", mapPtr->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at a", mapPtr->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at a", mapPtr->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at a", mapPtr->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at a", mapPtr->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at a", mapPtr->CS_to_PS_SRVCC_Indication == 1);
    ASSERTM("Indication data info test of CLII flag failed at a", mapPtr->ChangeOfLocationIndication == 0);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char b[] = { 0x4D,     0x12, 0x34,    0x06,       0x02    ,   0x02     ,   0x02     ,   0x02    };
    INDICATION_IE  *mapPtrb = (INDICATION_IE *) b;
    ASSERTM("Indication data info test of type field failed at b ", mapPtrb->type == 77);
    ASSERTM("Indication data info test of length field failed at b", mapPtrb->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at b", mapPtrb->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at b", mapPtrb->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at b", mapPtrb->IdleModeSignallingReductionActivationIndication == 1);
    ASSERTM("Indication data info test of ISRSI flag failed at b", mapPtrb->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at b", mapPtrb->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at b", mapPtrb->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at b", mapPtrb->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at b", mapPtrb->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at b", mapPtrb->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at b", mapPtrb->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at b", mapPtrb->ScopeIndication == 1);
    ASSERTM("Indication data info test of PT flag failed at b", mapPtrb->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at b", mapPtrb->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at b", mapPtr->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at b", mapPtrb->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at b", mapPtrb->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at b", mapPtrb->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at b", mapPtrb->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at b", mapPtrb->ISRIsActivatedOnUE == 1);
    ASSERTM("Indication data info test of MBMDT flag failed at b", mapPtrb->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at b", mapPtrb->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at b", mapPtrb->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at b", mapPtrb->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at b", mapPtrb->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at b", mapPtrb->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at b", mapPtrb->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at b", mapPtrb->ChangeOfLocationIndication == 1);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char c[] = { 0x4D,     0x12, 0x34,    0x06,       0x04    ,   0x04     ,   0x04     ,   0x04    };
    INDICATION_IE  *mapPtrc = (INDICATION_IE *) c;
    ASSERTM("Indication data info test of type field failed at c ", mapPtrc->type == 77);
    ASSERTM("Indication data info test of length field failed at c", mapPtrc->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at c", mapPtrc->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at c", mapPtrc->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at c", mapPtrc->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at c", mapPtrc->IdleModeSignallingReductionSupportedIndication == 1);
    ASSERTM("Indication data info test of OI flag failed at c", mapPtrc->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at c", mapPtrc->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at c", mapPtrc->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at c", mapPtrc->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at c", mapPtrc->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at c", mapPtrc->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at c", mapPtrc->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at c", mapPtrc->ProtocolType == 1);
    ASSERTM("Indication data info test of P flag failed at c", mapPtrc->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at c", mapPtrc->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at c", mapPtrc->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at c", mapPtrc->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at c", mapPtrc->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at c", mapPtrc->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at c", mapPtrc->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at c", mapPtrc->ManagementBasedMDTFlag == 1);
    ASSERTM("Indication data info test of S4AF flag failed at c", mapPtrc->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at c", mapPtrc->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at c", mapPtrc->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at c", mapPtrc->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at c", mapPtrc->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at c", mapPtrc->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at c", mapPtrc->ChangeOfLocationIndication == 0);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char d[] = { 0x4D,     0x12, 0x34,    0x06,       0x08    ,   0x08     ,   0x08     ,   0x08    };
    INDICATION_IE  *mapPtrd = (INDICATION_IE *) d;
    ASSERTM("Indication data info test of type field failed at d ", mapPtrd->type == 77);
    ASSERTM("Indication data info test of length field failed at d", mapPtrd->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at d", mapPtrd->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at d", mapPtrd->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at d", mapPtrd->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at d", mapPtrd->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at d", mapPtrd->OperationIndication == 1);
    ASSERTM("Indication data info test of DFI flag failed at d", mapPtrd->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at d", mapPtrd->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at d", mapPtrd->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at d", mapPtrd->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at d", mapPtrd->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at d", mapPtrd->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at d", mapPtrd->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at d", mapPtrd->PiggybackingSupported == 1);
    ASSERTM("Indication data info test of CRSI flag failed at d", mapPtrd->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at d", mapPtrd->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at d", mapPtrd->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at d", mapPtrd->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at d", mapPtrd->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at d", mapPtrd->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at d", mapPtrd->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at d", mapPtrd->StaticIPv4AddressFlag == 1);
    ASSERTM("Indication data info test of S6AF flag failed at d", mapPtrd->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at d", mapPtrd->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at d", mapPtrd->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at d", mapPtrd->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at d", mapPtrd->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at d", mapPtrd->ChangeOfLocationIndication == 0);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char e[] = { 0x4D,     0x12, 0x34,    0x06,       0x10    ,   0x10    ,   0x10     ,   0x10    };
    INDICATION_IE  *mapPtre = (INDICATION_IE *) e;
    ASSERTM("Indication data info test of type field failed at e ", mapPtre->type == 77);
    ASSERTM("Indication data info test of length field failed at e", mapPtre->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at e", mapPtre->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at e", mapPtre->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at e", mapPtre->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at e", mapPtre->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at e", mapPtre->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at e", mapPtre->DirectForwardingIndication == 1);
    ASSERTM("Indication data info test of HI flag failed at e", mapPtre->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at e", mapPtre->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at e", mapPtre->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at e", mapPtre->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at e", mapPtre->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at e", mapPtre->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at e", mapPtre->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at e", mapPtre->ChangeReportingSupportIndication == 1);
    ASSERTM("Indication data info test of CFSI flag failed at e", mapPtre->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at e", mapPtre->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at e", mapPtre->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at e", mapPtre->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at e", mapPtre->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at e", mapPtre->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at e", mapPtre->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at e", mapPtre->StaticIPv6AddressFlag == 1);
    ASSERTM("Indication data info test of SRNI flag failed at e", mapPtre->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at e", mapPtre->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at e", mapPtre->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at e", mapPtre->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at e", mapPtre->ChangeOfLocationIndication == 0);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char f[] = { 0x4D,     0x12, 0x34,    0x06,       0x20    ,   0x20    ,   0x20     ,   0x20    };
    INDICATION_IE  *mapPtrf = (INDICATION_IE *) f;
    ASSERTM("Indication data info test of type field failed at f ", mapPtrf->type == 77);
    ASSERTM("Indication data info test of length field failed at f", mapPtrf->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at f", mapPtrf->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at f", mapPtrf->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at f", mapPtrf->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at f", mapPtrf->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at f", mapPtrf->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at f", mapPtrf->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at f", mapPtrf->HandoverIndication == 1);
    ASSERTM("Indication data info test of DTF flag failed at f", mapPtrf->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at f", mapPtrf->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at f", mapPtrf->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at f", mapPtrf->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at f", mapPtrf->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at f", mapPtrf->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at f", mapPtrf->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at f", mapPtrf->ChangeFTEIDSupportIndication == 1);
    ASSERTM("Indication data info test of UIMSI flag failed at f", mapPtrf->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at f", mapPtrf->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at f", mapPtrf->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at f", mapPtrf->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at f", mapPtrf->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at f", mapPtrf->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at f", mapPtrf->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at f", mapPtrf->SGWRestorationNeededIndication == 1);
    ASSERTM("Indication data info test of PBIC flag failed at f", mapPtrf->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at f", mapPtrf->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at f", mapPtrf->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at f", mapPtrf->ChangeOfLocationIndication == 0);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char g[] = { 0x4D,     0x12, 0x34,    0x06,       0x40    ,   0x40    ,   0x40     ,   0x40    };
    INDICATION_IE  *mapPtrg = (INDICATION_IE *) g;
    ASSERTM("Indication data info test of type field failed at g ", mapPtrg->type == 77);
    ASSERTM("Indication data info test of length field failed at g", mapPtrg->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at g", mapPtrg->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at g", mapPtrg->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at g", mapPtrg->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at g", mapPtrg->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at g", mapPtrg->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at g", mapPtrg->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at g", mapPtrg->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at g", mapPtrg->DirectTunnelFlag == 1);
    ASSERTM("Indication data info test of DAF flag failed at g", mapPtrg->DualAddressBearerFlag == 0);
    ASSERTM("Indication data info test of MSV flag failed at g", mapPtrg->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at g", mapPtrg->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at g", mapPtrg->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at g", mapPtrg->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at g", mapPtrg->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at g", mapPtrg->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at g", mapPtrg->UnauthenticatedIMSI == 1);
    ASSERTM("Indication data info test of SQCI flag failed at g", mapPtrg->SubscribedQOSChangeIndication == 0);
    ASSERTM("Indication data info test of CCRSI flag failed at g", mapPtrg->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at g", mapPtrg->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at g", mapPtrg->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at g", mapPtrg->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at g", mapPtrg->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at g", mapPtrg->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at g", mapPtrg->PropagateBBAIInformationChange == 1);
    ASSERTM("Indication data info test of RetLoc flag failed at g", mapPtrg->RetriveLocationIndicationFlag == 0);
    ASSERTM("Indication data info test of CPSR flag failed at g", mapPtrg->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at g", mapPtrg->ChangeOfLocationIndication == 0);
    /*   type   len1  len2   spare/ins   flag byte 1, flag byte 2, flag byte 3, flag byte 4   */
    unsigned char h[] = { 0x4D,     0x12, 0x34,    0x06,       0x80    ,   0x80    ,   0x80     ,   0x80    };
    INDICATION_IE  *mapPtrh = (INDICATION_IE *) h;
    ASSERTM("Indication data info test of type field failed at h ", mapPtrh->type == 77);
    ASSERTM("Indication data info test of length field failed at h", mapPtrh->length == 0x3412);
    ASSERTM("Indication data info test of instance field failed at h", mapPtrh->instance == 6);
    ASSERTM("Indication data info test of SGWCI flag failed at h", mapPtrh->SGWChangeIndication == 0);
    ASSERTM("Indication data info test of ISRAI flag failed at h", mapPtrh->IdleModeSignallingReductionActivationIndication == 0);
    ASSERTM("Indication data info test of ISRSI flag failed at h", mapPtrh->IdleModeSignallingReductionSupportedIndication == 0);
    ASSERTM("Indication data info test of OI flag failed at h", mapPtrh->OperationIndication == 0);
    ASSERTM("Indication data info test of DFI flag failed at h", mapPtrh->DirectForwardingIndication == 0);
    ASSERTM("Indication data info test of HI flag failed at h", mapPtrh->HandoverIndication == 0);
    ASSERTM("Indication data info test of DTF flag failed at h", mapPtrh->DirectTunnelFlag == 0);
    ASSERTM("Indication data info test of DAF flag failed at h", mapPtrh->DualAddressBearerFlag == 1);
    ASSERTM("Indication data info test of MSV flag failed at h", mapPtrh->MSValidated == 0);
    ASSERTM("Indication data info test of SI flag failed at h", mapPtrh->ScopeIndication == 0);
    ASSERTM("Indication data info test of PT flag failed at h", mapPtrh->ProtocolType == 0);
    ASSERTM("Indication data info test of P flag failed at h", mapPtrh->PiggybackingSupported == 0);
    ASSERTM("Indication data info test of CRSI flag failed at h", mapPtrh->ChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of CFSI flag failed at h", mapPtrh->ChangeFTEIDSupportIndication == 0);
    ASSERTM("Indication data info test of UIMSI flag failed at h", mapPtrh->UnauthenticatedIMSI == 0);
    ASSERTM("Indication data info test of SQCI flag failed at h", mapPtrh->SubscribedQOSChangeIndication == 1);
    ASSERTM("Indication data info test of CCRSI flag failed at h", mapPtrh->CSGChangeReportingSupportIndication == 0);
    ASSERTM("Indication data info test of ISRAU flag failed at h", mapPtrh->ISRIsActivatedOnUE == 0);
    ASSERTM("Indication data info test of MBMDT flag failed at h", mapPtrh->ManagementBasedMDTFlag == 0);
    ASSERTM("Indication data info test of S4AF flag failed at h", mapPtrh->StaticIPv4AddressFlag == 0);
    ASSERTM("Indication data info test of S6AF flag failed at h", mapPtrh->StaticIPv6AddressFlag == 0);
    ASSERTM("Indication data info test of SRNI flag failed at h", mapPtrh->SGWRestorationNeededIndication == 0);
    ASSERTM("Indication data info test of PBIC flag failed at h", mapPtrh->PropagateBBAIInformationChange == 0);
    ASSERTM("Indication data info test of RetLoc flag failed at h", mapPtrh->RetriveLocationIndicationFlag == 1);
    ASSERTM("Indication data info test of CPSR flag failed at h", mapPtrh->CS_to_PS_SRVCC_Indication == 0);
    ASSERTM("Indication data info test of CLII flag failed at h", mapPtrh->ChangeOfLocationIndication == 0);
}

void TestCellGlobalIdentiferStruct() {
    /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  CI 1st B, CI 2nd B  as per 8.21.1 20974-b30 3GPP   */
    unsigned char a[] = { 0x21,     0x63,       0x54,    0x89,      0x67    ,   0x34,  0x12    };
    char mnc[MNC_MAX_CHARS], mcc[MCC_MAX_CHARS];
    CellGlobalIdentifer *mapPtr = (CellGlobalIdentifer *) a;
    decodeMCC(a, mcc);
    decodeMNC(a + 1, mnc);
    ASSERTM("CGI info test of MCC field failed at a ", !strcmp(mcc, "123"));
    //TODO find out if MNC is 321 or 312
    ASSERTM("CGI info test of MNC field failed at a ", !strcmp(mnc, "456"));
    ASSERTM("CGI info test of LAC field failed at a ", mapPtr->LocationAreaCode == 0x6789);
    ASSERTM("CGI info test of CI field failed at a ", mapPtr->CellIdentity == 0x1234);
}

void TestULISubIEIdentifaction() {
    //                        flag l1    l2    instance flags  CGI etc
    unsigned char a[] = { 0x56, 0x12, 0x34,    0x06,    0x1,
                          /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  CI 1st B, CI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                          0x21,     0x63,       0x54,    0x89,      0x67    ,   0x34,  0x12
                        };
    cout << sizeof(DecodedMsg_V2);
    DecodedMsg_V2 *pmsg = new DecodedMsg_V2();
    DecodeUserLocationInformation(a, 0, pmsg);
    ASSERTM("CGI info test of CI field failed at a ", pmsg->cgi == 0x3412);
    ASSERTM("CGI info test of LAC field failed at a ", pmsg->lac == 0x8967);
    //                        flag l1    l2    instance flags  CGI etc
    unsigned char b[] = { 0x56, 0x12, 0x34,    0x06,    0x2,
                          /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  SAI 1st B, SAI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                          0x21,     0x63,       0x54,    0x89,      0x67    ,   0x34,  0x12
                        };
    pmsg->lac = 0;
    pmsg->cgi = 0;
    DecodeUserLocationInformation(b, 0, pmsg);
    ASSERTM("CGI info test of LAC field failed at b ", pmsg->lac == 0x8967);
    ASSERTM("CGI info test of SAI field failed at b ", pmsg->sai == 0x3412);
    unsigned char c[] = { 0x56, 0x12, 0x34,    0x06,    0x4,
                          /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  RAI 1st B, RAI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                          0x21,     0x63,       0x54,    0x89,      0x67    ,   0x34,  0x12
                        };
    pmsg->lac = 0;
    pmsg->sai = 0;
    DecodeUserLocationInformation(c, 0, pmsg);
    ASSERTM("CGI info test of LAC field failed at c ", pmsg->lac == 0x8967);
    ASSERTM("CGI info test of RAI field failed at c ", pmsg->rai == 0x3412);
    unsigned char d[] = { 0x56, 0x12, 0x34,    0x06,    0x8,
                          /*   MCC 2-1,  MNC3 MCC3, MNC 2-1,   TAI 1st B, TAI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                          0x21,     0x63,       0x54,   0x34,  0x12
                        };
    pmsg->lac = 0;
    pmsg->rai = 0;
    DecodeUserLocationInformation(d, 0, pmsg);
    ASSERTM("CGI info test of TAI field failed at d ", pmsg->tai == 0x3412);
    unsigned char e[] = { 0x56, 0x12, 0x34,    0x06,    0x10,
                          /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, spare/ ECGI 1st B, ECGI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                          0x21,     0x63,       0x54,    0x98,      0x67    ,   0x34,  0x02
                        };
    pmsg->lac = 0;
    pmsg->sai = 0;
    DecodeUserLocationInformation(e, 0, pmsg);
    ASSERTM("CGI info test of ECGI field failed at e ", pmsg->ecgi == 0x2346798);
    unsigned char f[] = { 0x56, 0x12, 0x34,    0x06,    0x20,
                          /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B  as per 8.21.1 20974-b30 3GPP   */
                          0x21,     0x63,       0x54,    0x89,      0x67
                        };
    pmsg->lac = 0;
    pmsg->ecgi = 0;
    DecodeUserLocationInformation(f, 0, pmsg);
    ASSERTM("CGI info test of LAC field failed at f ", pmsg->lac == 0x8967);
    unsigned char RunAll[] = { 0x56, 0x12, 0x34,    0x06,    0x3f,
                               /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  CI 1st B, CI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                               0x00,     0x00,       0x00,    0x67,      0x89    ,   0x12,  0x43,
                               /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  SAI 1st B, SAI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                               0x00,     0x00,       0x00,    0x67,      0x89    ,   0x21,  0x54,
                               /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B,  RAI 1st B, RAI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                               0x00,     0x00,       0x00,    0x67,      0x89    ,   0x12,  0x56,
                               /*   MCC 2-1,  MNC3 MCC3, MNC 2-1,   TAI 1st B, TAI 2nd B  as per 8.21.1 20974-b30 3GPP   */
                               0x00,     0x00,       0x00,   0x23,  0x14,
                               /*   MCC 2-1,  MNC3 MCC3, MNC 2-1,   spare/ECI ,  ECI         ECI    ECI as per 8.21.1 20974-b30 3GPP   */
                               0x00,     0x00,       0x00,    0x67,      0x89    ,   0x98,  0x45,
                               /*   MCC 2-1,  MNC3 MCC3, MNC 2-1, LAC 1st B, LAC 2nd B  as per 8.21.1 20974-b30 3GPP   */
                               0x00,     0x00,       0x00,    0x67,      0x89
                             };
    pmsg->cgi = 0;
    pmsg->sai = 0;
    pmsg->rai = 0;
    pmsg->tai = 0;
    pmsg->ecgi = 0;
    pmsg->lac = 0;
    DecodeUserLocationInformation(RunAll, 0, pmsg);
    ASSERTM("ULI info test of CGI field failed at RunAll ", pmsg->cgi == 0x1243);
    ASSERTM("ULI info test of SAI field failed at RunAll ", pmsg->sai == 0x2154);
    ASSERTM("ULI info test of RAI field failed at RunAll ", pmsg->rai == 0x1256);
    ASSERTM("ULI info test of TAI field failed at RunAll ", pmsg->tai == 0x2314);
    ASSERTM("ULI info test of ECGI field failed at RunAll ", pmsg->ecgi == 0x5988967);
    ASSERTM("ULI info test of LAI field failed at RunAll ", pmsg->lac == 0x6789);
    delete pmsg;
}

void testPDUNumbersStruct() {
    /*   type   len1  len2   spare/ins   nsapi/spare  ,   DL-gtpu 1  DL-gtpu 2 ,   ul-gtpu1  ul-gtpu 2, send n-PDU 1 send n-PDU 2, re n-pdu 1 re n-pdu 2                    */
    unsigned char a[] = { 0x6E,     0x12, 0x34,    0x06,       0x08    ,   0x89    ,   0x67     ,   0x34    ,   0x12   ,    0x86   ,    0x79      ,     0x54 ,    0x21     };
    PDU_Numbers_IE  *mapPtr = (PDU_Numbers_IE *) a;
    ASSERTM("PDUNumbers data info test of type flag failed at a", mapPtr->type == 0x6E);
    ASSERTM("PDUNumbers data info test of length flag failed at a", mapPtr->length == 0x3412);
    ASSERTM("PDUNumbers data info test of NSAPI flag failed at a", mapPtr->NSAPI == 0x08);
    ASSERTM("PDUNumbers data info test of DL GTP-U flag failed at a", mapPtr->DL_GTPUSequenceNumber == 0x6789);
    ASSERTM("PDUNumbers data info test of UL GTP-U flag failed at a", mapPtr->UL_GTPUSequenceNumber == 0x1234);
    ASSERTM("PDUNumbers data info test of send N-PDU flag failed at a", mapPtr->sendN_PDUNumber == 0x7986);
    ASSERTM("PDUNumbers data info test of recive N-PDU flag failed at a", mapPtr->receiveN_PDUNumber == 0x2154);
}

void testBearerQualityOfService_IEStruct() {
    /*   type   len1  len2   spare/ins  PVI/spare/PL/PCI/spare  ,   QCI,      max bit rate UL      ..    ..    ..  ,    max bit rate DL      ..    ..    ..  ,  guaranteed bit rate ul  ..    ..    ..  , guaranteed bit rate Dl  ..    ..    .. */
    unsigned char a[] = { 0x6E,     0x12, 0x34,    0x06,       0x55              ,   0x89    ,   0x91     , 0x78 , 0x56, 0x34, 0x12 ,      0x12     , 0x34 , 0x56, 0x78, 0x91 ,       0x91     , 0x78 , 0x56, 0x34, 0x12 ,      0x12     , 0x34 , 0x56, 0x78, 0x91};
    BearerQualityOfService_IE  *mapPtr = (BearerQualityOfService_IE *) a;
    ASSERTM("BearerQualityOfService_IE data info test of type flag failed at a", mapPtr->type == 0x6E);
    ASSERTM("BearerQualityOfService_IE data info test of length flag failed at a", mapPtr->length == 0x3412);
    ASSERTM("BearerQualityOfService_IE data info test of PVI flag failed at a", mapPtr->PVI == 1);
    ASSERTM("BearerQualityOfService_IE data info test of PL flag failed at a", mapPtr->PL == 0x05);
    ASSERTM("BearerQualityOfService_IE data info test of PCI flag failed at a", mapPtr->PCI == 1);
    ASSERTM("BearerQualityOfService_IE data info test of QCI flag failed at a", mapPtr->LabelQCI == 0x89);
    ASSERTM("BearerQualityOfService_IE data info test of MaxBitrateUpLink flag failed at a", mapPtr->MaxBitrateUpLink == 0x1234567891);
    ASSERTM("BearerQualityOfService_IE data info test of MaxBitrateDownLink flag failed at a", mapPtr->MaxBitrateDownLink == 0x9178563412);
    ASSERTM("BearerQualityOfService_IE data info test of GuaranteedBitRateUL flag failed at a", mapPtr->GuaranteedBitRateUL == 0x1234567891);
    ASSERTM("BearerQualityOfService_IE data info test of GuaranteedBitRateDL flag failed at a", mapPtr->GuaranteedBitRateDL == 0x9178563412);
}

void testReverseArrayData() {
    unsigned char a[] = { 0x6E,     0x12, 0x34,    0x06,       0x55  };
    //ASSERTM("failed to reverse value", reverseArrayData(a,5,0)== 0x550634126e);
    //ASSERTM("failed to maintain value", reverseArrayData(a,5,0)== 0x6E12340655);
}

void testfullyQulifiedTEID() {
    /*   type   len1  len2   spare/ins    interfaceType/v6/v4 ,   TEID_GRE  ........... */
    unsigned char a[] = { 0x57,     0x12, 0x34,    0x0f,       0x10               ,   0x89, 0x91, 0x78, 0x56 };
    fullyQuilifedTEID *mapPTR = (fullyQuilifedTEID *) a;
    ASSERTM("check fully qulified TEID, instance", mapPTR->instance == 0x0f);
    ASSERTM("check fully qualified TEID, interface type", mapPTR->interfaceType == 0x10);
    /*   type   len1  len2   spare/ins    interfaceType/v6/v4 ,   TEID_GRE  ........... */
    unsigned char b[] = { 0x57,     0x12, 0x34,    0x0f,       0xcf               ,   0x89, 0x91, 0x78, 0x56 };
    fullyQuilifedTEID *mapPTRb = (fullyQuilifedTEID *) b;
    ASSERTM("check fully qulified TEID, instance", mapPTRb->instance == 0x0f);
    ASSERTM("check fully qualified TEID, interface type", mapPTRb->interfaceType == 0x0f);
    ASSERTM("check fully qualified TEID, v4", mapPTRb->V4 == 1);
    ASSERTM("check fully qualified TEID, v6", mapPTRb->V6 == 1);
}

void testS1_U_Data_Forwarding() {
    /*   type   len1  len2   spare/ins     EPS Bearer ID,   Serving GW Address Length, address data          , TEID */
    unsigned char a[] = { 0x57,     0x12, 0x34,    0x0f,       0x02      ,   0x04,                      0xff, 0xff, 0xff, 0xff, 0x89, 0x67, 0x45, 0x23};
    S1_U_Data_Forwarding *mapPTR = (S1_U_Data_Forwarding *) a;
    ASSERTM("check S1-U", mapPTR->EPS_Bearer_ID == 0x02);
    ASSERTM("check S1-U", mapPTR->servingGWAddressLength == 0x04);
    int offset = sizeof(S1_U_Data_Forwarding) + mapPTR->servingGWAddressLength;
    ASSERTM("check S1-U, TEID", (NetworkIntAt(a + offset)) == 0x89674523);
}

cute::suite runGTPV2IESuite(cute::suite s) {
    s.push_back(CUTE(TestIndicationStruct));
    s.push_back(CUTE(TestULISubIEIdentifaction));
    s.push_back(CUTE(TestUserLocationInformationStruct));
    s.push_back(CUTE(TestCellGlobalIdentiferStruct));
    //  s.push_back(CUTE(testParseIMSI_IMEIFields));
    s.push_back(CUTE(testPDUNumbersStruct));
    s.push_back(CUTE(testBearerQualityOfService_IEStruct));
    s.push_back(CUTE(testReverseArrayData));
    s.push_back(CUTE(testfullyQulifiedTEID));
    s.push_back(CUTE(testS1_U_Data_Forwarding));
    return s;
}

// Re-enable the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
