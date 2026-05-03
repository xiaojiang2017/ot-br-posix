/*
 *  Copyright (c) 2024, Custom OpenThread Border Router Extension.
 *  All rights reserved.
 *
 *  This file is an independent extension for ot-br-posix.
 *  It registers a separate "otbr-agent" ubus object to avoid
 *  conflicts with the official "otbr" ubus object.
 *
 *  Features:
 *    - Query methods: version / status / threadinfo / getaddrs / dataset / topology / getevents
 *    - State change callback: monitors role, network config, dataset changes
 *    - Neighbor table callback: monitors direct child/router add/remove/mode-change
 *    - Topology scan: detects all router/child changes network-wide
 *    - ubus event broadcast: real-time events via `ubus listen otbr-agent.*`
 */

#define OTBR_LOG_TAG "UBUS_AGENT"

#include "openwrt/ubus/otubus_agent.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <queue>
#include <set>
#include <string>

#include <arpa/inet.h>

#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>
#include <openthread/dns.h>
#include <openthread/dns_client.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/message.h>
#include <openthread/netdata.h>
#include <openthread/platform/radio.h>
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/backbone_router.h>
#include <openthread/backbone_router_ftd.h>
#include <openthread/border_agent.h>
#include <openthread/border_routing.h>
#include <openthread/commissioner.h>
#include <openthread/joiner.h>
#include <openthread/nat64.h>
#include <openthread/srp_server.h>
#include <openthread/dnssd_server.h>
#include <openthread/mesh_diag.h>

#if OTBR_ENABLE_BORDER_AGENT
#include "border_agent/border_agent.hpp"
#endif
#include "common/logging.hpp"
#include "ncp/ncp_openthread.hpp"
#include "utils/pskc.hpp"

extern "C" {
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
}

namespace otbr {
namespace ubus {

static UbusAgentExt *sAgentInstance = nullptr;

static bool ParseOtbrLogLevel(const char *aValue, otLogLevel &aLevel)
{
    if (aValue == nullptr || *aValue == '\0')
    {
        return false;
    }

    char *endPtr = nullptr;
    long  parsed = strtol(aValue, &endPtr, 10);

    if (endPtr != nullptr && *endPtr == '\0')
    {
        if (OT_LOG_LEVEL_NONE <= parsed && parsed <= OT_LOG_LEVEL_DEBG)
        {
            aLevel = static_cast<otLogLevel>(parsed);
            return true;
        }

        return false;
    }

    struct LogLevelName
    {
        const char *mName;
        otLogLevel  mLevel;
    };

    static const LogLevelName kLevels[] = {
        {"none", OT_LOG_LEVEL_NONE},
        {"crit", OT_LOG_LEVEL_CRIT},
        {"critical", OT_LOG_LEVEL_CRIT},
        {"warn", OT_LOG_LEVEL_WARN},
        {"warning", OT_LOG_LEVEL_WARN},
        {"note", OT_LOG_LEVEL_NOTE},
        {"notice", OT_LOG_LEVEL_NOTE},
        {"info", OT_LOG_LEVEL_INFO},
        {"debug", OT_LOG_LEVEL_DEBG},
        {"debg", OT_LOG_LEVEL_DEBG},
    };

    for (const LogLevelName &entry : kLevels)
    {
        if (strcasecmp(aValue, entry.mName) == 0)
        {
            aLevel = entry.mLevel;
            return true;
        }
    }

    return false;
}

static void AddBlobMsgBool(struct blob_buf *aBuf, const char *aKey, bool aValue)
{
    uint8_t value = aValue ? 1 : 0;

    blobmsg_add_field(aBuf, BLOBMSG_TYPE_BOOL, aKey, &value, sizeof(value));
}

static std::string SecondsToHmsString(uint32_t aSeconds)
{
    uint32_t hours   = aSeconds / 3600;
    uint32_t minutes = (aSeconds % 3600) / 60;
    uint32_t seconds = aSeconds % 60;
    char     buf[32];

    snprintf(buf, sizeof(buf), "%u:%02u:%02u", hours, minutes, seconds);
    return std::string(buf);
}

static const char *NetDataPreferenceToString(int aPreference)
{
    switch (aPreference)
    {
    case OT_ROUTE_PREFERENCE_LOW:
        return "low";
    case OT_ROUTE_PREFERENCE_MED:
        return "med";
    case OT_ROUTE_PREFERENCE_HIGH:
        return "high";
    default:
        return "unknown";
    }
}

static std::string NetDataPrefixFlagsToString(const otBorderRouterConfig &aConfig)
{
    std::string flags;

    if (aConfig.mPreferred)
    {
        flags.push_back('p');
    }
    if (aConfig.mSlaac)
    {
        flags.push_back('a');
    }
    if (aConfig.mDhcp)
    {
        flags.push_back('d');
    }
    if (aConfig.mConfigure)
    {
        flags.push_back('c');
    }
    if (aConfig.mDefaultRoute)
    {
        flags.push_back('r');
    }
    if (aConfig.mOnMesh)
    {
        flags.push_back('o');
    }
    if (aConfig.mStable)
    {
        flags.push_back('s');
    }
    if (aConfig.mNdDns)
    {
        flags.push_back('n');
    }
    if (aConfig.mDp)
    {
        flags.push_back('D');
    }

    return flags;
}

static std::string NetDataRouteFlagsToString(const otExternalRouteConfig &aConfig)
{
    std::string flags;

    if (aConfig.mStable)
    {
        flags.push_back('s');
    }
    if (aConfig.mNat64)
    {
        flags.push_back('n');
    }
    if (aConfig.mAdvPio)
    {
        flags.push_back('a');
    }

    return flags;
}

static const char *NetDataServiceName(const otServiceConfig &aConfig)
{
    if (aConfig.mServiceDataLength == 1 && aConfig.mServiceData[0] == 0x01)
    {
        return "BBR";
    }

    if (aConfig.mServiceDataLength == 1 && aConfig.mServiceData[0] == 0x5d)
    {
        return "SRP server";
    }

    return nullptr;
}

static bool ShouldUseLocalDatasetSet(otDeviceRole aRole)
{
    return aRole == OT_DEVICE_ROLE_DISABLED || aRole == OT_DEVICE_ROLE_DETACHED;
}

static otError SetOrSendActiveDataset(otInstance            *aInstance,
                                      otOperationalDataset  *aDataset,
                                      uint8_t               *aTlvs,
                                      uint8_t                aTlvsLength)
{
    if (ShouldUseLocalDatasetSet(otThreadGetDeviceRole(aInstance)))
    {
        return otDatasetSetActive(aInstance, aDataset);
    }

    return otDatasetSendMgmtActiveSet(aInstance, aDataset, aTlvs, aTlvsLength,
                                      /* aCallback */ nullptr,
                                      /* aContext */ nullptr);
}

// ===================== Policy definitions =====================

enum
{
    DATASET_TYPE,
    DATASET_MAX,
};

static const struct blobmsg_policy datasetPolicy[DATASET_MAX] = {
    [DATASET_TYPE] = {.name = "type", .type = BLOBMSG_TYPE_STRING},
};

enum
{
    EVENTS_COUNT,
    EVENTS_MAX,
};

static const struct blobmsg_policy getEventsPolicy[EVENTS_MAX] = {
    [EVENTS_COUNT] = {.name = "count", .type = BLOBMSG_TYPE_INT32},
};

enum
{
    JOINER_PSKD,
    JOINER_PROVISIONING_URL,
    JOINER_VENDOR_NAME,
    JOINER_VENDOR_MODEL,
    JOINER_VENDOR_SW_VERSION,
    JOINER_VENDOR_DATA,
    JOINER_START_MAX,
};

static const struct blobmsg_policy joinerStartPolicy[JOINER_START_MAX] = {
    [JOINER_PSKD]              = {.name = "pskd",              .type = BLOBMSG_TYPE_STRING},
    [JOINER_PROVISIONING_URL]  = {.name = "provisioning_url",  .type = BLOBMSG_TYPE_STRING},
    [JOINER_VENDOR_NAME]       = {.name = "vendor_name",       .type = BLOBMSG_TYPE_STRING},
    [JOINER_VENDOR_MODEL]      = {.name = "vendor_model",      .type = BLOBMSG_TYPE_STRING},
    [JOINER_VENDOR_SW_VERSION] = {.name = "vendor_sw_version", .type = BLOBMSG_TYPE_STRING},
    [JOINER_VENDOR_DATA]       = {.name = "vendor_data",       .type = BLOBMSG_TYPE_STRING},
};

enum
{
    JOINER_ADD_EUI64,
    JOINER_ADD_DISCERNER_VALUE,
    JOINER_ADD_DISCERNER_LENGTH,
    JOINER_ADD_PSKD,
    JOINER_ADD_TIMEOUT,
    JOINER_ADD_MAX,
};

static const struct blobmsg_policy joinerAddPolicy[JOINER_ADD_MAX] = {
    [JOINER_ADD_EUI64]           = {.name = "eui64",            .type = BLOBMSG_TYPE_STRING},
    [JOINER_ADD_DISCERNER_VALUE] = {.name = "discerner_value",  .type = BLOBMSG_TYPE_INT64},
    [JOINER_ADD_DISCERNER_LENGTH]= {.name = "discerner_length", .type = BLOBMSG_TYPE_INT32},
    [JOINER_ADD_PSKD]            = {.name = "pskd",             .type = BLOBMSG_TYPE_STRING},
    [JOINER_ADD_TIMEOUT]         = {.name = "timeout",          .type = BLOBMSG_TYPE_INT32},
};

enum
{
    JOINER_REMOVE_EUI64,
    JOINER_REMOVE_DISCERNER_VALUE,
    JOINER_REMOVE_DISCERNER_LENGTH,
    JOINER_REMOVE_MAX,
};

static const struct blobmsg_policy joinerRemovePolicy[JOINER_REMOVE_MAX] = {
    [JOINER_REMOVE_EUI64]           = {.name = "eui64",            .type = BLOBMSG_TYPE_STRING},
    [JOINER_REMOVE_DISCERNER_VALUE] = {.name = "discerner_value",  .type = BLOBMSG_TYPE_INT64},
    [JOINER_REMOVE_DISCERNER_LENGTH]= {.name = "discerner_length", .type = BLOBMSG_TYPE_INT32},
};

enum
{
    COMMISSIONER_START_TIMEOUT,
    COMMISSIONER_START_MAX,
};

static const struct blobmsg_policy commissionerStartPolicy[COMMISSIONER_START_MAX] = {
    [COMMISSIONER_START_TIMEOUT] = {.name = "timeout", .type = BLOBMSG_TYPE_INT32},
};

enum
{
    MDNS_VENDOR_NAME,
    MDNS_PRODUCT_NAME,
    MDNS_INSTANCE_NAME,
    MDNS_VENDOR_OUI,
    MDNS_MAX,
};

static const struct blobmsg_policy setMdnsPolicy[MDNS_MAX] = {
    [MDNS_VENDOR_NAME]   = {.name = "vendor_name",   .type = BLOBMSG_TYPE_STRING},
    [MDNS_PRODUCT_NAME]  = {.name = "product_name",  .type = BLOBMSG_TYPE_STRING},
    [MDNS_INSTANCE_NAME] = {.name = "instance_name", .type = BLOBMSG_TYPE_STRING},
    [MDNS_VENDOR_OUI]    = {.name = "vendor_oui",    .type = BLOBMSG_TYPE_STRING},
};

enum
{
    SET_BBR_ENABLED,
    SET_BBR_SEQUENCE_NUMBER,
    SET_BBR_REREGISTRATION_DELAY,
    SET_BBR_MLR_TIMEOUT,
    SET_BBR_REGISTER,
    SET_BBR_JITTER,
    SET_BBR_MAX,
};

static const struct blobmsg_policy setBbrPolicy[SET_BBR_MAX] = {
    [SET_BBR_ENABLED]              = {.name = "enabled",              .type = BLOBMSG_TYPE_BOOL},
    [SET_BBR_SEQUENCE_NUMBER]      = {.name = "sequence_number",      .type = BLOBMSG_TYPE_INT32},
    [SET_BBR_REREGISTRATION_DELAY] = {.name = "reregistration_delay", .type = BLOBMSG_TYPE_INT32},
    [SET_BBR_MLR_TIMEOUT]          = {.name = "mlr_timeout",          .type = BLOBMSG_TYPE_INT32},
    [SET_BBR_REGISTER]             = {.name = "register",             .type = BLOBMSG_TYPE_BOOL},
    [SET_BBR_JITTER]               = {.name = "jitter",               .type = BLOBMSG_TYPE_INT32},
};

enum
{
    SET_SRP_ENABLED,
    SET_SRP_AUTO_ENABLE,
    SET_SRP_ADDRESS_MODE,
    SET_SRP_ANYCAST_SEQ,
    SET_SRP_DOMAIN,
    SET_SRP_MIN_LEASE,
    SET_SRP_MAX_LEASE,
    SET_SRP_MIN_KEY_LEASE,
    SET_SRP_MAX_KEY_LEASE,
    SET_SRP_MIN_TTL,
    SET_SRP_MAX_TTL,
    SET_SRP_MAX,
};

static const struct blobmsg_policy setSrpServerPolicy[SET_SRP_MAX] = {
    [SET_SRP_ENABLED]       = {.name = "enabled",        .type = BLOBMSG_TYPE_BOOL},
    [SET_SRP_AUTO_ENABLE]   = {.name = "auto_enable",    .type = BLOBMSG_TYPE_BOOL},
    [SET_SRP_ADDRESS_MODE]  = {.name = "address_mode",   .type = BLOBMSG_TYPE_STRING},
    [SET_SRP_ANYCAST_SEQ]   = {.name = "anycast_seq",    .type = BLOBMSG_TYPE_INT32},
    [SET_SRP_DOMAIN]        = {.name = "domain",         .type = BLOBMSG_TYPE_STRING},
    [SET_SRP_MIN_LEASE]     = {.name = "min_lease",      .type = BLOBMSG_TYPE_INT32},
    [SET_SRP_MAX_LEASE]     = {.name = "max_lease",      .type = BLOBMSG_TYPE_INT32},
    [SET_SRP_MIN_KEY_LEASE] = {.name = "min_key_lease",  .type = BLOBMSG_TYPE_INT32},
    [SET_SRP_MAX_KEY_LEASE] = {.name = "max_key_lease",  .type = BLOBMSG_TYPE_INT32},
    [SET_SRP_MIN_TTL]       = {.name = "min_ttl",        .type = BLOBMSG_TYPE_INT32},
    [SET_SRP_MAX_TTL]       = {.name = "max_ttl",        .type = BLOBMSG_TYPE_INT32},
};

enum
{
    SET_NAT64_ENABLED,
    SET_NAT64_CIDR,
    SET_NAT64_DNS_UPSTREAM,
    SET_NAT64_MAX,
};

static const struct blobmsg_policy setNat64Policy[SET_NAT64_MAX] = {
    [SET_NAT64_ENABLED]      = {.name = "enabled",       .type = BLOBMSG_TYPE_BOOL},
    [SET_NAT64_CIDR]         = {.name = "cidr",          .type = BLOBMSG_TYPE_STRING},
    [SET_NAT64_DNS_UPSTREAM] = {.name = "dns_upstream",  .type = BLOBMSG_TYPE_BOOL},
};

enum
{
    MESHDIAG_IP6_ADDRS,
    MESHDIAG_CHILDREN,
    MESHDIAG_CHILDTABLE,
    MESHDIAG_CHILDIP6,
    MESHDIAG_ROUTERNEIGHBORTABLE,
    MESHDIAG_MAX,
};

static const struct blobmsg_policy meshDiagPolicy[MESHDIAG_MAX] = {
    [MESHDIAG_IP6_ADDRS]            = {.name = "ip6_addrs",            .type = BLOBMSG_TYPE_BOOL},
    [MESHDIAG_CHILDREN]             = {.name = "children",             .type = BLOBMSG_TYPE_BOOL},
    [MESHDIAG_CHILDTABLE]           = {.name = "childtable",           .type = BLOBMSG_TYPE_BOOL},
    [MESHDIAG_CHILDIP6]             = {.name = "childip6",             .type = BLOBMSG_TYPE_BOOL},
    [MESHDIAG_ROUTERNEIGHBORTABLE]  = {.name = "routerneighbortable",  .type = BLOBMSG_TYPE_BOOL},
};

// Policy for discover method (optional channel parameter)
enum
{
    DISCOVER_CHANNEL,
    DISCOVER_MAX,
};

static const struct blobmsg_policy discoverPolicy[DISCOVER_MAX] = {
    [DISCOVER_CHANNEL] = {.name = "channel", .type = BLOBMSG_TYPE_INT32},
};

enum
{
    SET_TX_POWER,
    SET_TX_POWER_MAX,
};

static const struct blobmsg_policy setTxPowerPolicy[SET_TX_POWER_MAX] = {
    [SET_TX_POWER] = {.name = "power", .type = BLOBMSG_TYPE_INT32},
};

// Policy for setnetworkconfig method (network configuration via Active Dataset)
enum
{
    MGMTSET_NETWORKKEY,
    MGMTSET_NETWORKNAME,
    MGMTSET_EXTPANID,
    MGMTSET_PANID,
    MGMTSET_CHANNEL,
    MGMTSET_PSKC,
    MGMTSET_TIMESTAMP,
    MGMTSET_MAX,
};

static const struct blobmsg_policy mgmtsetPolicy[MGMTSET_MAX] = {
    [MGMTSET_NETWORKKEY]   = {.name = "networkkey",   .type = BLOBMSG_TYPE_STRING},
    [MGMTSET_NETWORKNAME]  = {.name = "networkname",  .type = BLOBMSG_TYPE_STRING},
    [MGMTSET_EXTPANID]     = {.name = "extpanid",     .type = BLOBMSG_TYPE_STRING},
    [MGMTSET_PANID]        = {.name = "panid",        .type = BLOBMSG_TYPE_STRING},
    [MGMTSET_CHANNEL]      = {.name = "channel",      .type = BLOBMSG_TYPE_STRING},
    [MGMTSET_PSKC]         = {.name = "pskc",         .type = BLOBMSG_TYPE_STRING},
    [MGMTSET_TIMESTAMP]    = {.name = "timestamp",    .type = BLOBMSG_TYPE_INT32},
};

// Policy for setdataset method (dataset configuration with passphrase or direct dataset TLVs)
enum
{
    SETDATASET_PASSPHRASE,
    SETDATASET_NETWORKNAME,
    SETDATASET_EXTPANID,
    SETDATASET_DATASET,
    SETDATASET_MAX,
};

static const struct blobmsg_policy setDatasetPolicy[SETDATASET_MAX] = {
    [SETDATASET_PASSPHRASE]  = {.name = "passphrase",  .type = BLOBMSG_TYPE_STRING},
    [SETDATASET_NETWORKNAME] = {.name = "networkname", .type = BLOBMSG_TYPE_STRING},
    [SETDATASET_EXTPANID]    = {.name = "extpanid",    .type = BLOBMSG_TYPE_STRING},
    [SETDATASET_DATASET]     = {.name = "dataset",     .type = BLOBMSG_TYPE_STRING},
};

enum
{
    SRPNETSERVICE_SERVICE,
    SRPNETSERVICE_DOMAIN,
    SRPNETSERVICE_RESOLVE,
    SRPNETSERVICE_TIMEOUT,
    SRPNETSERVICE_ATTEMPTS,
    SRPNETSERVICE_MAX,
};

static const struct blobmsg_policy srpNetServicePolicy[SRPNETSERVICE_MAX] = {
    [SRPNETSERVICE_SERVICE]  = {.name = "service",  .type = BLOBMSG_TYPE_STRING},
    [SRPNETSERVICE_DOMAIN]   = {.name = "domain",   .type = BLOBMSG_TYPE_STRING},
    [SRPNETSERVICE_RESOLVE]  = {.name = "resolve",  .type = BLOBMSG_TYPE_BOOL},
    [SRPNETSERVICE_TIMEOUT]  = {.name = "timeout",  .type = BLOBMSG_TYPE_INT32},
    [SRPNETSERVICE_ATTEMPTS] = {.name = "attempts", .type = BLOBMSG_TYPE_INT32},
};

// =================== ubus method table =======================

static const struct ubus_method otbrAgentMethods[] = {
    {"version",    &UbusAgentExt::HandleVersion,    0, 0, nullptr,         0},
    {"status",     &UbusAgentExt::HandleStatus,     0, 0, nullptr,         0},
    {"threadinfo", &UbusAgentExt::HandleThreadInfo,  0, 0, nullptr,         0},
    {"rloc16",     &UbusAgentExt::HandleRloc16,     0, 0, nullptr,         0},
    {"getaddrs",   &UbusAgentExt::HandleGetAddrs,    0, 0, nullptr,         0},
    {"dataset",    &UbusAgentExt::HandleDataset,     0, 0, datasetPolicy,   ARRAY_SIZE(datasetPolicy)},
    {"topology",   &UbusAgentExt::HandleTopology,    0, 0, nullptr,         0},
    {"getevents",  &UbusAgentExt::HandleGetEvents,   0, 0, getEventsPolicy, ARRAY_SIZE(getEventsPolicy)},
    {"bbrstatus",  &UbusAgentExt::HandleBbr,         0, 0, nullptr,         0},
    {"leaderdata", &UbusAgentExt::HandleLeaderData,  0, 0, nullptr,         0},
    {"joinerstate",&UbusAgentExt::HandleJoinerState, 0, 0, nullptr,         0},
    {"joinerstart",&UbusAgentExt::HandleJoinerStart, 0, 0, joinerStartPolicy, ARRAY_SIZE(joinerStartPolicy)},
    {"joinerstop", &UbusAgentExt::HandleJoinerStop,  0, 0, nullptr,         0},
    {"joineradd",  &UbusAgentExt::HandleJoinerAdd,   0, 0, joinerAddPolicy,   ARRAY_SIZE(joinerAddPolicy)},
    {"joinerremove",&UbusAgentExt::HandleJoinerRemove, 0, 0, joinerRemovePolicy, ARRAY_SIZE(joinerRemovePolicy)},
    {"uciconfig",  &UbusAgentExt::HandleUciConfig,   0, 0, nullptr,         0},
    {"uciapply",   &UbusAgentExt::HandleUciApply,    0, 0, nullptr,         0},
    {"setmdns",    &UbusAgentExt::HandleSetMdns,     0, 0, setMdnsPolicy,   ARRAY_SIZE(setMdnsPolicy)},
    {"commissionerstart", &UbusAgentExt::HandleCommissionerStart, 0, 0, commissionerStartPolicy, ARRAY_SIZE(commissionerStartPolicy)},
    {"commissionerstop",  &UbusAgentExt::HandleCommissionerStop,  0, 0, nullptr, 0},
    {"commissionerstate", &UbusAgentExt::HandleCommissionerstate, 0, 0, nullptr, 0},
    {"setbbrconfig",      &UbusAgentExt::HandleSetBbr,            0, 0, setBbrPolicy, ARRAY_SIZE(setBbrPolicy)},
    {"setsrpserver",      &UbusAgentExt::HandleSetSrpServer,      0, 0, setSrpServerPolicy, ARRAY_SIZE(setSrpServerPolicy)},
    {"setsrpsrvconfig",   &UbusAgentExt::HandleSetSrpServerConfig, 0, 0, setSrpServerPolicy, ARRAY_SIZE(setSrpServerPolicy)},
    {"setnat64config",    &UbusAgentExt::HandleSetNat64,          0, 0, setNat64Policy, ARRAY_SIZE(setNat64Policy)},
    {"setnetworkconfig",  &UbusAgentExt::HandleSetnetworkconfig,  0, 0, mgmtsetPolicy, ARRAY_SIZE(mgmtsetPolicy)},
    {"mgmtset",           &UbusAgentExt::HandleMgmtset,           0, 0, mgmtsetPolicy, ARRAY_SIZE(mgmtsetPolicy)},
    {"omrprefix",         &UbusAgentExt::HandleOmrPrefix,         0, 0, nullptr, 0},
    {"onlinkprefix",      &UbusAgentExt::HandleOnLinkPrefix,      0, 0, nullptr, 0},
    {"getprefix",         &UbusAgentExt::HandleGetprefix,         0, 0, nullptr, 0},
    {"getomrprefix",      &UbusAgentExt::HandleGetOmrPrefix,      0, 0, nullptr, 0},
    {"meshdiag",          &UbusAgentExt::HandleMeshDiag,          0, 0, meshDiagPolicy, ARRAY_SIZE(meshDiagPolicy)},
    // Additional query methods from patch reference
    {"srpsrvconfig",      &UbusAgentExt::HandleSrpsrvconfig,      0, 0, nullptr, 0},
    {"srpsrvservice",     &UbusAgentExt::HandleSrpsrvservice,     0, 0, nullptr, 0},
    {"srpnetservice",     &UbusAgentExt::HandleSrpNetService,     0, 0, srpNetServicePolicy, ARRAY_SIZE(srpNetServicePolicy)},
    {"services",          &UbusAgentExt::HandleServices,          0, 0, nullptr, 0},
    {"netdata",           &UbusAgentExt::HandleNetdata,           0, 0, nullptr, 0},
    {"neighbortable",     &UbusAgentExt::HandleNeighbortable,     0, 0, nullptr, 0},
    {"nat64status",       &UbusAgentExt::HandleNat64status,       0, 0, nullptr, 0},
    {"routerlist",        &UbusAgentExt::HandleRouterlist,        0, 0, nullptr, 0},
    // State query and thread control methods
    {"state",             &UbusAgentExt::HandleState,             0, 0, nullptr, 0},
    {"pskc",              &UbusAgentExt::HandlePskc,              0, 0, nullptr, 0},
    {"threadstart",       &UbusAgentExt::HandleThreadStart,       0, 0, nullptr, 0},
    {"threadstop",        &UbusAgentExt::HandleThreadStop,        0, 0, nullptr, 0},
    {"joinernum",         &UbusAgentExt::HandleJoinerNum,         0, 0, nullptr, 0},
    {"setleaderrole",     &UbusAgentExt::HandleSetLeaderRole,     0, 0, nullptr, 0},
    {"setdataset",        &UbusAgentExt::HandleSetDataset,        0, 0, setDatasetPolicy, ARRAY_SIZE(setDatasetPolicy)},
    {"discover",          &UbusAgentExt::HandleDiscover,          0, 0, discoverPolicy,   ARRAY_SIZE(discoverPolicy)},
    {"bufferinfo",        &UbusAgentExt::HandleBufferInfo,        0, 0, nullptr,         0},
    {"txpower",           &UbusAgentExt::HandleTxPower,           0, 0, nullptr,         0},
    {"settxpower",        &UbusAgentExt::HandleSetTxPower,        0, 0, setTxPowerPolicy, ARRAY_SIZE(setTxPowerPolicy)},
};

static struct ubus_object_type otbrAgentObjType = {
    "otbr_agent_prog", 0, otbrAgentMethods, ARRAY_SIZE(otbrAgentMethods)
};

static struct ubus_object otbrAgentObj = {
    avl           : {},
    name          : "otbr-agent",
    id            : 0,
    path          : nullptr,
    type          : &otbrAgentObjType,
    subscribe_cb  : nullptr,
    has_subscribers : false,
    methods       : otbrAgentMethods,
    n_methods     : ARRAY_SIZE(otbrAgentMethods),
};

// =================== Constructor / Singleton ==================

UbusAgentExt::UbusAgentExt(Ncp::ControllerOpenThread *aController, std::mutex *aMutex)
    : mController(aController)
    , mNcpThreadMutex(aMutex)
    , mUbusContext(nullptr)
    , mLastRole(OT_DEVICE_ROLE_DISABLED)
    , mCallbacksRegistered(false)
    , mTopologyInitialized(false)
    , mUciApplied(false)
    , mMeshDiagPhase(kMeshDiagIdle)
    , mMeshDiagRouterIdx(0)
    , mMeshDiagDone(false)
    , mMeshDiagWantChildTable(true)
    , mMeshDiagWantChildIp6(true)
    , mMeshDiagWantRouterNeighbor(true)
    , mMeshDiagFinalError(OT_ERROR_NONE)
    , mMeshDiagUbusCtx(nullptr)
#if OTBR_ENABLE_BORDER_AGENT
    , mBorderAgent(nullptr)
    , mHasPendingMdnsServiceConfig(false)
#endif
{
    memset(&mBuf, 0, sizeof(mBuf));
    memset(&mEventBuf, 0, sizeof(mEventBuf));
    memset(&mEventDrainTimer, 0, sizeof(mEventDrainTimer));
    memset(&mCommissionerTimeoutTimer, 0, sizeof(mCommissionerTimeoutTimer));
    memset(&mMeshDiagDeferredReq, 0, sizeof(mMeshDiagDeferredReq));
    memset(&mSrpNetServiceDeferredReq, 0, sizeof(mSrpNetServiceDeferredReq));
    mSrpNetServiceUbusCtx    = nullptr;
    mSrpNetServiceBusy       = false;
    mSrpNetServiceDone       = false;
    mSrpNetServiceResolve    = true;
    mSrpNetServiceResolveIdx = 0;
    mSrpNetServiceFinalError = OT_ERROR_NONE;
    memset(&mSrpNetServiceQueryConfig, 0, sizeof(mSrpNetServiceQueryConfig));
    blob_buf_init(&mBuf, 0);
    blob_buf_init(&mEventBuf, 0);
}

void UbusAgentExt::Initialize(Ncp::ControllerOpenThread *aController, std::mutex *aMutex)
{
    sAgentInstance = new UbusAgentExt(aController, aMutex);
}

UbusAgentExt &UbusAgentExt::GetInstance(void)
{
    return *sAgentInstance;
}

int UbusAgentExt::RegisterObject(struct ubus_context *aContext)
{
    if (ubus_add_object(aContext, &otbrAgentObj) != 0)
    {
        otbrLogErr("Failed to add otbr-agent ubus object");
        return -1;
    }

    mUbusContext = aContext;

    // Set up a periodic timer in the ubus uloop to drain pending events.
    // This ensures ubus_send_event() is only called from the ubus thread.
    mEventDrainTimer.cb = &UbusAgentExt::HandleEventDrainTimer;
    uloop_timeout_set(&mEventDrainTimer, 200); // 200ms initial

    otbrLogInfo("otbr-agent ubus object registered successfully");
    return 0;
}

void UbusAgentExt::RegisterOtCallbacks(void)
{
    if (mCallbacksRegistered)
    {
        return;
    }

    // 1) State changed callback — use ot-br-posix's AddThreadStateChangedCallback
    //    This is safe and supports multiple callbacks.
    mController->AddThreadStateChangedCallback([](otChangedFlags aFlags) {
        UbusAgentExt::GetInstance().HandleStateChanged(aFlags);
    });

    // 2) Neighbor table callback — register via OpenThread API
    //    WARNING: This overwrites any previous callback. Since the upstream
    //    ot-br-posix does NOT use this callback, it is safe for now.
    mNcpThreadMutex->lock();
    otThreadRegisterNeighborTableCallback(mController->GetInstance(),
                                          &UbusAgentExt::HandleNeighborTableChanged);
    mNcpThreadMutex->unlock();

    mCallbacksRegistered = true;
    otbrLogInfo("otbr-agent: OpenThread callbacks registered");

    // 3) Try auto-start from UCI config (if autostart=1)
    TryAutoStartFromUci();
}

// ======================== Helpers =============================

/**
 * Add Rloc16 as both numeric (Rloc16) and string (Rloc16s) format to mBuf.
 * @param[in] aKey  The key name for the numeric field (e.g., "rloc16")
 * @param[in] aRloc16  The RLOC16 value
 */
void UbusAgentExt::AddRloc16ToBlob(struct blob_buf *aBuf, const char *aKey, uint16_t aRloc16)
{
    char rloc16Str[16];

    // Add numeric value (e.g., "rloc16": 0x0400 or decimal 1024)
    blobmsg_add_u32(aBuf, aKey, aRloc16);

    // Add string value with "0x" prefix (e.g., "rloc16s": "0x0400")
    snprintf(rloc16Str, sizeof(rloc16Str), "0x%04x", aRloc16);
    blobmsg_add_string(aBuf, (std::string(aKey) + "s").c_str(), rloc16Str);
}

const char *UbusAgentExt::RoleToString(otDeviceRole aRole)
{
    switch (aRole)
    {
    case OT_DEVICE_ROLE_DISABLED:
        return "disabled";
    case OT_DEVICE_ROLE_DETACHED:
        return "detached";
    case OT_DEVICE_ROLE_CHILD:
        return "child";
    case OT_DEVICE_ROLE_ROUTER:
        return "router";
    case OT_DEVICE_ROLE_LEADER:
        return "leader";
    default:
        return "unknown";
    }
}

static bool IsThreadAttachedRole(otDeviceRole aRole)
{
    return aRole == OT_DEVICE_ROLE_CHILD || aRole == OT_DEVICE_ROLE_ROUTER || aRole == OT_DEVICE_ROLE_LEADER;
}

void UbusAgentExt::OutputBytes(const uint8_t *aBytes, uint8_t aLength, char *aOutput)
{
    char byte2char[5] = "";
    aOutput[0]        = '\0';

    for (int i = 0; i < aLength; i++)
    {
        sprintf(byte2char, "%02x", aBytes[i]);
        strcat(aOutput, byte2char);
    }
}

void UbusAgentExt::OutputBytesToUpper(const uint8_t *aBytes, uint8_t aLength, char *aOutput)
{
    char byte2char[5] = "";
    aOutput[0]        = '\0';

    for (int i = 0; i < aLength; i++)
    {
        sprintf(byte2char, "%02X", aBytes[i]);
        strcat(aOutput, byte2char);
    }
}

const char *UbusAgentExt::NeighborEventToString(otNeighborTableEvent aEvent)
{
    switch (aEvent)
    {
    case OT_NEIGHBOR_TABLE_EVENT_CHILD_ADDED:
        return "child_added";
    case OT_NEIGHBOR_TABLE_EVENT_CHILD_REMOVED:
        return "child_removed";
    case OT_NEIGHBOR_TABLE_EVENT_CHILD_MODE_CHANGED:
        return "child_mode_changed";
    case OT_NEIGHBOR_TABLE_EVENT_ROUTER_ADDED:
        return "neighbor_router_added";
    case OT_NEIGHBOR_TABLE_EVENT_ROUTER_REMOVED:
        return "neighbor_router_removed";
    default:
        return "unknown";
    }
}

void UbusAgentExt::AddEventLog(const std::string &aType, const std::string &aDetail)
{
    std::lock_guard<std::mutex> lock(mEventLogMutex);

    EventLogEntry entry;
    entry.mTimestamp = time(nullptr);
    entry.mType      = aType;
    entry.mDetail    = aDetail;

    mEventLog.push_back(entry);

    // Ring buffer: remove oldest entries
    while (mEventLog.size() > kMaxEventLogSize)
    {
        mEventLog.pop_front();
    }
}

void UbusAgentExt::SendUbusEvent(const char *aEventName, struct blob_attr *aData)
{
    // Do NOT call ubus_send_event() here — this may be called from the main thread
    // while ubus_context is owned by the ubus thread. Enqueue instead.
    EnqueueUbusEvent(aEventName, aData);
}

void UbusAgentExt::EnqueueUbusEvent(const char *aEventName, struct blob_attr *aData)
{
    PendingUbusEvent evt;
    evt.mEventName = aEventName;

    // Serialize blob to JSON string so we don't carry blob_attr across threads
    char *jsonStr = blobmsg_format_json(aData, true);
    if (jsonStr != nullptr)
    {
        evt.mJsonData = jsonStr;
        free(jsonStr);
    }

    {
        std::lock_guard<std::mutex> lock(mPendingEventsMutex);
        // Limit queue size to avoid unbounded growth
        if (mPendingEvents.size() < 256)
        {
            mPendingEvents.push(std::move(evt));
        }
    }
}

void UbusAgentExt::HandleEventDrainTimer(struct uloop_timeout *aTimeout)
{
    if (sAgentInstance != nullptr)
    {
        sAgentInstance->DrainPendingEvents();
    }

    // Re-arm the timer (200ms)
    uloop_timeout_set(aTimeout, 200);
}

void UbusAgentExt::DrainPendingEvents(void)
{
    std::queue<PendingUbusEvent> pending;

    {
        std::lock_guard<std::mutex> lock(mPendingEventsMutex);
        std::swap(pending, mPendingEvents);
    }

    if (mUbusContext == nullptr)
    {
        return;
    }

    struct blob_buf b;
    memset(&b, 0, sizeof(b));

    while (!pending.empty())
    {
        const PendingUbusEvent &evt = pending.front();

        blob_buf_init(&b, 0);
        if (!evt.mJsonData.empty() &&
            blobmsg_add_json_from_string(&b, evt.mJsonData.c_str()))
        {
            ubus_send_event(mUbusContext, evt.mEventName.c_str(), b.head);
        }

        pending.pop();
    }

    blob_buf_free(&b);

    // Check if deferred requests are complete
    CompleteMeshDiagDeferred();
    CompleteSrpNetServiceDeferred();
}

// ================ Handler: version ============================
// ubus call otbr-agent version
// Returns: { "version": "...", "api_version": "..." }

int UbusAgentExt::HandleVersion(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
                                struct ubus_request_data *aRequest,
                                const char               *aMethod,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().VersionDetail(aContext, aRequest);
}

int UbusAgentExt::VersionDetail(struct ubus_context      *aContext,
                                struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    blobmsg_add_string(&mBuf, "OtVersion", otGetVersionString());
    blobmsg_add_string(&mBuf, "OtRcpVersion", otGetRadioVersionString(mController->GetInstance()));
    blobmsg_add_string(&mBuf, "AgentVersion", OTBR_PACKAGE_VERSION);
    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: status =============================
// ubus call otbr-agent status
// Returns: { "role": "...", "rloc16": "0x...", "eui64": "...", "extaddr": "..." }

int UbusAgentExt::HandleStatus(struct ubus_context      *aContext,
                               struct ubus_object       *aObj,
                               struct ubus_request_data *aRequest,
                               const char               *aMethod,
                               struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().StatusDetail(aContext, aRequest);
}

int UbusAgentExt::StatusDetail(struct ubus_context      *aContext,
                               struct ubus_request_data *aRequest)
{
    char extPanId[17]    = {0};
    char networkKey[33]  = {0};
    char PSKc[33]        = {0};
    char activeDataset[(OT_OPERATIONAL_DATASET_MAX_LENGTH * 2) + 1] = {0};
    char extAddress[17]  = {0};

    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // Version info
    blobmsg_add_u16(&mBuf, "OpenThreadVersionAPI", OPENTHREAD_API_VERSION);
    blobmsg_add_string(&mBuf, "OTBRVersion", otGetVersionString());
    if (otThreadGetVersion() == 4)
        blobmsg_add_string(&mBuf, "ThreadVersion", "v1.3.0");
    else if (otThreadGetVersion() == 3)
        blobmsg_add_string(&mBuf, "ThreadVersion", "v1.2.0");
    else if (otThreadGetVersion() == 2)
        blobmsg_add_string(&mBuf, "ThreadVersion", "v1.1.0");
    else
        blobmsg_add_string(&mBuf, "ThreadVersion", "unknown");

    uint8_t rloc = otThreadGetDeviceRole(instance);

    /* Network Item */
    void *pNetwork = blobmsg_open_table(&mBuf, "Network");
    blobmsg_add_u16(&mBuf, "Channel", otLinkGetChannel(instance));

    const uint8_t *pExtPanId = reinterpret_cast<const uint8_t *>(otThreadGetExtendedPanId(instance));
    OutputBytes(pExtPanId, OT_EXT_PAN_ID_SIZE, extPanId);
    blobmsg_add_string(&mBuf, "ExtPanId", extPanId);

    otNetworkKey t_networkKey;
    otThreadGetNetworkKey(instance, &t_networkKey);
    const uint8_t *pNetworkKey = reinterpret_cast<const uint8_t *>(t_networkKey.m8);
    OutputBytes(pNetworkKey, OT_NETWORK_KEY_SIZE, networkKey);
    blobmsg_add_string(&mBuf, "NetworkKey", networkKey);

    blobmsg_add_string(&mBuf, "NetworkName", otThreadGetNetworkName(instance));
    blobmsg_add_u32(&mBuf, "PanId", otLinkGetPanId(instance));

    otPskc t_pskc;
    otThreadGetPskc(instance, &t_pskc);
    const uint8_t *pPSKc = reinterpret_cast<const uint8_t *>(t_pskc.m8);
    OutputBytes(pPSKc, OT_PSKC_MAX_SIZE, PSKc);
    blobmsg_add_string(&mBuf, "PSKc", PSKc);

    otOperationalDatasetTlvs datasetTlvs;
    if (otDatasetGetActiveTlvs(instance, &datasetTlvs) == OT_ERROR_NONE)
    {
        OutputBytes(datasetTlvs.mTlvs, datasetTlvs.mLength, activeDataset);
        blobmsg_add_string(&mBuf, "ActiveDataset", activeDataset);
    }

    // OnMeshPrefix
    void *pOnMeshPrefix = blobmsg_open_array(&mBuf, "OnMeshPrefix");
    if (pOnMeshPrefix)
    {
        otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
        otBorderRouterConfig  config;
        while (otNetDataGetNextOnMeshPrefix(instance, &iterator, &config) == OT_ERROR_NONE)
        {
            char str[OT_IP6_ADDRESS_STRING_SIZE] = {0};
            otIp6PrefixToString(&config.mPrefix, str, sizeof(str));
            blobmsg_add_string(&mBuf, nullptr, str);
        }
        blobmsg_close_array(&mBuf, pOnMeshPrefix);
    }

    if (rloc != OT_DEVICE_ROLE_DISABLED && rloc != OT_DEVICE_ROLE_DETACHED)
    {
        void        *pLeaderdata = blobmsg_open_table(&mBuf, "LeaderData");
        if (pLeaderdata)
        {
            otLeaderData leaderData;
            otThreadGetLeaderData(instance, &leaderData);
            blobmsg_add_u32(&mBuf, "PartitionId", leaderData.mPartitionId);
            blobmsg_add_u32(&mBuf, "Weighting", leaderData.mWeighting);
            blobmsg_add_u32(&mBuf, "DataVersion", leaderData.mDataVersion);
            blobmsg_add_u32(&mBuf, "StableDataVersion", leaderData.mStableDataVersion);
            blobmsg_add_u32(&mBuf, "LeaderRouterId", leaderData.mLeaderRouterId);
            blobmsg_close_table(&mBuf, pLeaderdata);
        }
    }

    char                     meshLocalPrefix[32] = {0};
    const otMeshLocalPrefix *aPrefix             = otThreadGetMeshLocalPrefix(instance);
    if (aPrefix != NULL)
    {
        sprintf(meshLocalPrefix, "%x:%x:%x:%x::/64", (aPrefix->m8[0] << 8) | aPrefix->m8[1],
                (aPrefix->m8[2] << 8) | aPrefix->m8[3], (aPrefix->m8[4] << 8) | aPrefix->m8[5],
                (aPrefix->m8[6] << 8) | aPrefix->m8[7]);
        blobmsg_add_string(&mBuf, "MeshLocalPrefix", meshLocalPrefix);
    }

    // IPv6 addresses
    void *pIPv6 = blobmsg_open_table(&mBuf, "IPv6");
    if (pIPv6)
    {
        const otNetifAddress *unicastAddrs = otIp6GetUnicastAddresses(instance);
        for (const otNetifAddress *addr = unicastAddrs; addr; addr = addr->mNext)
        {
            char string[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6AddressToString(&addr->mAddress, string, sizeof(string));
            blobmsg_add_string(&mBuf, nullptr, string);
        }
        blobmsg_close_table(&mBuf, pIPv6);
    }

    char            borderAgentIdString[OT_BORDER_AGENT_ID_LENGTH * 2 + 1] = {0};
    otBorderAgentId id;
    otBorderAgentGetId(instance, &id);
    OutputBytes(id.mId, OT_BORDER_AGENT_ID_LENGTH, borderAgentIdString);
    blobmsg_add_string(&mBuf, "BorderAgentID", borderAgentIdString);

    blobmsg_close_table(&mBuf, pNetwork);

    /* RCP Item */
    void *pRCP = blobmsg_open_table(&mBuf, "RCP");
    if (pRCP)
    {
        if (rloc == OT_DEVICE_ROLE_DISABLED)
            blobmsg_add_u16(&mBuf, "State", 0);
        else if (rloc == OT_DEVICE_ROLE_DETACHED)
            blobmsg_add_u16(&mBuf, "State", 1);
        else if (rloc == OT_DEVICE_ROLE_CHILD)
            blobmsg_add_u16(&mBuf, "State", 2);
        else if (rloc == OT_DEVICE_ROLE_ROUTER)
            blobmsg_add_u16(&mBuf, "State", 3);
        else if (rloc == OT_DEVICE_ROLE_LEADER)
            blobmsg_add_u16(&mBuf, "State", 4);

        OutputBytes(reinterpret_cast<const uint8_t *>(otLinkGetExtendedAddress(instance)),
                    OT_EXT_ADDRESS_SIZE, extAddress);
        blobmsg_add_string(&mBuf, "ExtAddress", extAddress);
        AddRloc16ToBlob(&mBuf, "Rloc16", otThreadGetRloc16(instance));
        blobmsg_close_table(&mBuf, pRCP);
    }

    /* SRP Item */
    void *pSRP = blobmsg_open_table(&mBuf, "SRP");
    if (pSRP)
    {
        blobmsg_add_u32(&mBuf, "ServerState", otSrpServerGetState(instance));
        blobmsg_add_string(&mBuf, "ServerDomain", otSrpServerGetDomain(instance));
        blobmsg_close_table(&mBuf, pSRP);
    }

    /* Commissioner Item */
    void *pCommissioner = blobmsg_open_table(&mBuf, "Commissioner");
    if (pCommissioner)
    {
        blobmsg_add_u32(&mBuf, "State", otCommissionerGetState(instance));
        blobmsg_close_table(&mBuf, pCommissioner);
    }

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: threadinfo =========================
// ubus call otbr-agent threadinfo
// Returns comprehensive Thread network info including active dataset
// (equivalent to `ot-ctl dataset active`)

int UbusAgentExt::HandleThreadInfo(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().ThreadInfoDetail(aContext, aRequest);
}

int UbusAgentExt::ThreadInfoDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest)
{
    char eui64str[OT_EXT_ADDRESS_SIZE * 2 + 1]   = "";
    char extaddrstr[OT_EXT_ADDRESS_SIZE * 2 + 1]  = "";

    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // Role
    blobmsg_add_string(&mBuf, "Role", RoleToString(otThreadGetDeviceRole(instance)));

    // RLOC16 (numeric + string)
    AddRloc16ToBlob(&mBuf, "Rloc16", otThreadGetRloc16(instance));

    // EUI64
    otExtAddress eui64;
    otLinkGetFactoryAssignedIeeeEui64(instance, &eui64);
    OutputBytes(eui64.m8, OT_EXT_ADDRESS_SIZE, eui64str);
    blobmsg_add_string(&mBuf, "Eui64", eui64str);

    // Extended Address
    const otExtAddress *extAddr = otLinkGetExtendedAddress(instance);
    OutputBytes(extAddr->m8, OT_EXT_ADDRESS_SIZE, extaddrstr);
    blobmsg_add_string(&mBuf, "ExtAddr", extaddrstr);

    // Partition ID
    blobmsg_add_u32(&mBuf, "PartitionId", otThreadGetPartitionId(instance));

    // Leader data
    otLeaderData leaderData;
    if (otThreadGetLeaderData(instance, &leaderData) == OT_ERROR_NONE)
    {
        void *leaderTbl = blobmsg_open_table(&mBuf, "Leader");
        blobmsg_add_u32(&mBuf, "PartitionId", leaderData.mPartitionId);
        blobmsg_add_u32(&mBuf, "Weighting", leaderData.mWeighting);
        blobmsg_add_u32(&mBuf, "DataVersion", leaderData.mDataVersion);
        blobmsg_add_u32(&mBuf, "StableDataVersion", leaderData.mStableDataVersion);
        blobmsg_add_u32(&mBuf, "RouterId", leaderData.mLeaderRouterId);
        blobmsg_close_table(&mBuf, leaderTbl);
    }

    // Active Dataset (equivalent to `ot-ctl dataset active`)
    otOperationalDataset dataset;
    otError              dsError = otDatasetGetActive(instance, &dataset);

    if (dsError == OT_ERROR_NONE)
    {
        void *dsTbl = blobmsg_open_table(&mBuf, "ActiveDataset");

        // Active Timestamp
        if (dataset.mComponents.mIsActiveTimestampPresent)
        {
            blobmsg_add_u64(&mBuf, "ActiveTimestamp", dataset.mActiveTimestamp.mSeconds);
        }

        // Network Name
        if (dataset.mComponents.mIsNetworkNamePresent)
        {
            blobmsg_add_string(&mBuf, "NetworkName", dataset.mNetworkName.m8);
        }

        // Channel
        if (dataset.mComponents.mIsChannelPresent)
        {
            blobmsg_add_u32(&mBuf, "Channel", dataset.mChannel);
        }

        // Channel Mask
        if (dataset.mComponents.mIsChannelMaskPresent)
        {
            char maskstr[12];
            snprintf(maskstr, sizeof(maskstr), "0x%08x", dataset.mChannelMask);
            blobmsg_add_string(&mBuf, "ChannelMask", maskstr);
        }

        // PAN ID
        if (dataset.mComponents.mIsPanIdPresent)
        {
            char panidstr[12];
            snprintf(panidstr, sizeof(panidstr), "0x%04x", dataset.mPanId);
            blobmsg_add_string(&mBuf, "PanId", panidstr);
        }

        // Extended PAN ID
        if (dataset.mComponents.mIsExtendedPanIdPresent)
        {
            char xpanidstr[OT_EXT_PAN_ID_SIZE * 2 + 1] = "";
            OutputBytes(dataset.mExtendedPanId.m8, OT_EXT_PAN_ID_SIZE, xpanidstr);
            blobmsg_add_string(&mBuf, "ExtPanId", xpanidstr);
        }

        // Network Key
        if (dataset.mComponents.mIsNetworkKeyPresent)
        {
            char networkkeystr[OT_NETWORK_KEY_SIZE * 2 + 1] = "";
            OutputBytes(dataset.mNetworkKey.m8, OT_NETWORK_KEY_SIZE, networkkeystr);
            blobmsg_add_string(&mBuf, "NetworkKey", networkkeystr);
        }

        // PSKc
        if (dataset.mComponents.mIsPskcPresent)
        {
            char pskcstr[OT_PSKC_MAX_SIZE * 2 + 1] = "";
            OutputBytes(dataset.mPskc.m8, OT_PSKC_MAX_SIZE, pskcstr);
            blobmsg_add_string(&mBuf, "Pskc", pskcstr);
        }

        // Mesh Local Prefix
        if (dataset.mComponents.mIsMeshLocalPrefixPresent)
        {
            otIp6Prefix mlPrefix;
            memset(&mlPrefix, 0, sizeof(mlPrefix));
            memcpy(mlPrefix.mPrefix.mFields.m8, dataset.mMeshLocalPrefix.m8,
                   OT_IP6_PREFIX_SIZE);
            mlPrefix.mLength = OT_IP6_PREFIX_BITSIZE;

            char mlpStr[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6PrefixToString(&mlPrefix, mlpStr, sizeof(mlpStr));
            blobmsg_add_string(&mBuf, "MeshLocalPrefix", mlpStr);
        }

        // Security Policy
        if (dataset.mComponents.mIsSecurityPolicyPresent)
        {
            void *spTbl = blobmsg_open_table(&mBuf, "SecurityPolicy");
            blobmsg_add_u32(&mBuf, "RotationTime", dataset.mSecurityPolicy.mRotationTime);
            blobmsg_add_u8(&mBuf, "ObtainNetworkKey",
                           (dataset.mSecurityPolicy.mObtainNetworkKeyEnabled) ? 1 : 0);
            blobmsg_add_u8(&mBuf, "NativeCommissioning",
                           (dataset.mSecurityPolicy.mNativeCommissioningEnabled) ? 1 : 0);
            blobmsg_add_u8(&mBuf, "Routers",
                           (dataset.mSecurityPolicy.mRoutersEnabled) ? 1 : 0);
            blobmsg_add_u8(&mBuf, "ExternalCommissioning",
                           (dataset.mSecurityPolicy.mExternalCommissioningEnabled) ? 1 : 0);
            blobmsg_close_table(&mBuf, spTbl);
        }

        // Raw TLV hex
        otOperationalDatasetTlvs datasetTlvs;
        if (otDatasetGetActiveTlvs(instance, &datasetTlvs) == OT_ERROR_NONE)
        {
            char tlvHex[OT_OPERATIONAL_DATASET_MAX_LENGTH * 2 + 1] = "";
            OutputBytes(datasetTlvs.mTlvs, datasetTlvs.mLength, tlvHex);
            blobmsg_add_string(&mBuf, "DatasetTlvs", tlvHex);
            blobmsg_add_u32(&mBuf, "DatasetLen", datasetTlvs.mLength);
        }

        blobmsg_close_table(&mBuf, dsTbl);
    }

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: rloc16 ============================
// ubus call otbr-agent rloc16
// Returns: { "Rloc16": 1024, "Rloc16s": "0x0400" }

int UbusAgentExt::HandleRloc16(struct ubus_context      *aContext,
                               struct ubus_object       *aObj,
                               struct ubus_request_data *aRequest,
                               const char               *aMethod,
                               struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().Rloc16Detail(aContext, aRequest);
}

int UbusAgentExt::Rloc16Detail(struct ubus_context      *aContext,
                               struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    AddRloc16ToBlob(&mBuf, "Rloc16", otThreadGetRloc16(mController->GetInstance()));
    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: leaderdata =========================
// ubus call otbr-agent leaderdata
// Returns: leader partition ID, weighting, data/stable versions,
//          leader router ID, and leader RLOC16

int UbusAgentExt::HandleLeaderData(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().LeaderDataDetail(aContext, aRequest);
}

int UbusAgentExt::LeaderDataDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otLeaderData leaderData;
    otError      error = otThreadGetLeaderData(instance, &leaderData);

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_u32(&mBuf, "PartitionId", leaderData.mPartitionId);
        blobmsg_add_u32(&mBuf, "Weighting", leaderData.mWeighting);
        blobmsg_add_u32(&mBuf, "DataVersion", leaderData.mDataVersion);
        blobmsg_add_u32(&mBuf, "StableDataVersion", leaderData.mStableDataVersion);
        blobmsg_add_u32(&mBuf, "LeaderRouterId", leaderData.mLeaderRouterId);

        // Leader RLOC16 = (router_id << 10)
        uint16_t leaderRloc16 = (uint16_t)(leaderData.mLeaderRouterId << 10);
        AddRloc16ToBlob(&mBuf, "LeaderRloc16", leaderRloc16);
    }
    else
    {
        blobmsg_add_string(&mBuf, "Error", "not_available");
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", error);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: joinerstate ========================
// ubus call otbr-agent joinerstate
// Returns: commissioner state, session ID, and list of registered joiners

int UbusAgentExt::HandleJoinerState(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
                                    struct ubus_request_data *aRequest,
                                    const char               *aMethod,
                                    struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().JoinerStateDetail(aContext, aRequest);
}

int UbusAgentExt::JoinerStateDetail(struct ubus_context      *aContext,
                                    struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // Commissioner state
    otCommissionerState commState = otCommissionerGetState(instance);
    const char *stateStr = "disabled";
    switch (commState)
    {
    case OT_COMMISSIONER_STATE_DISABLED:
        stateStr = "disabled";
        break;
    case OT_COMMISSIONER_STATE_PETITION:
        stateStr = "petition";
        break;
    case OT_COMMISSIONER_STATE_ACTIVE:
        stateStr = "active";
        break;
    }
    blobmsg_add_string(&mBuf, "CommissionerState", stateStr);

    // Commissioner ID
    blobmsg_add_string(&mBuf, "CommissionerId", otCommissionerGetId(instance));

    // Commissioning dataset (session ID, joiner UDP port)
    if (commState != OT_COMMISSIONER_STATE_DISABLED)
    {
        blobmsg_add_u32(&mBuf, "SessionId", otCommissionerGetSessionId(instance));
    }

    // List all registered joiners
    void    *joinerArray = blobmsg_open_array(&mBuf, "Joiners");
    uint16_t iterator    = 0;
    otJoinerInfo joinerInfo;

    while (otCommissionerGetNextJoinerInfo(instance, &iterator, &joinerInfo) == OT_ERROR_NONE)
    {
        void *joinerItem = blobmsg_open_table(&mBuf, nullptr);

        // Joiner type
        const char *typeStr = "any";
        switch (joinerInfo.mType)
        {
        case OT_JOINER_INFO_TYPE_ANY:
            typeStr = "any";
            break;
        case OT_JOINER_INFO_TYPE_EUI64:
        {
            typeStr = "eui64";
            char eui64Str[OT_EXT_ADDRESS_SIZE * 2 + 1] = "";
            OutputBytes(joinerInfo.mSharedId.mEui64.m8, OT_EXT_ADDRESS_SIZE, eui64Str);
            blobmsg_add_string(&mBuf, "Eui64", eui64Str);
            break;
        }
        case OT_JOINER_INFO_TYPE_DISCERNER:
            typeStr = "discerner";
            blobmsg_add_u64(&mBuf, "DiscernerValue", joinerInfo.mSharedId.mDiscerner.mValue);
            blobmsg_add_u32(&mBuf, "DiscernerLength", joinerInfo.mSharedId.mDiscerner.mLength);
            break;
        }
        blobmsg_add_string(&mBuf, "Type", typeStr);

        // PSKd
        blobmsg_add_string(&mBuf, "Pskd", joinerInfo.mPskd.m8);

        // Expiration time (ms)
        blobmsg_add_u32(&mBuf, "ExpirationMs", joinerInfo.mExpirationTime);

        blobmsg_close_table(&mBuf, joinerItem);
    }

    blobmsg_close_array(&mBuf, joinerArray);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: joinerstart ========================
// ubus call otbr-agent joinerstart '{"pskd":"J01NME"}'
// Optional: provisioning_url, vendor_name, vendor_model, vendor_sw_version, vendor_data
// Returns: error code from otJoinerStart

int UbusAgentExt::HandleJoinerStart(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
                                    struct ubus_request_data *aRequest,
                                    const char               *aMethod,
                                    struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().JoinerStartDetail(aContext, aRequest, aMsg);
}

void JoinerCallback(otError aError, void *aContext)
{
    OT_UNUSED_VARIABLE(aContext);

    if (sAgentInstance != nullptr)
    {
        sAgentInstance->HandleJoinerCallback(aError);
    }
}

void UbusAgentExt::HandleJoinerCallback(otError aError)
{
    const char *resultStr = "unknown";
    switch (aError)
    {
    case OT_ERROR_NONE:
        resultStr = "success";
        break;
    case OT_ERROR_SECURITY:
        resultStr = "security_error";
        break;
    case OT_ERROR_NOT_FOUND:
        resultStr = "no_network_found";
        break;
    case OT_ERROR_RESPONSE_TIMEOUT:
        resultStr = "timeout";
        break;
    default:
        break;
    }

    otbrLogInfo("otbr-agent: joiner completed: %s (error=%d)", resultStr, aError);

    // Log event
    std::string detail = std::string("joiner_result:") + resultStr;
    AddEventLog("joiner", detail);

    // Broadcast ubus event
    blob_buf_init(&mEventBuf, 0);
    blobmsg_add_string(&mEventBuf, "event", "joiner_completed");
    blobmsg_add_string(&mEventBuf, "result", resultStr);
    blobmsg_add_u32(&mEventBuf, "error_code", aError);

    // Include current joiner state
    otInstance *instance = mController->GetInstance();
    blobmsg_add_string(&mEventBuf, "joiner_state",
                       otJoinerStateToString(otJoinerGetState(instance)));

    blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
    SendUbusEvent("otbr-agent.joiner", mEventBuf.head);
}

int UbusAgentExt::JoinerStartDetail(struct ubus_context      *aContext,
                                    struct ubus_request_data *aRequest,
                                    struct blob_attr         *aMsg)
{
    struct blob_attr *tb[JOINER_START_MAX];
    const char       *pskd            = nullptr;
    const char       *provisioningUrl = nullptr;
    const char       *vendorName      = nullptr;
    const char       *vendorModel     = nullptr;
    const char       *vendorSwVersion = nullptr;
    const char       *vendorData      = nullptr;

    blob_buf_init(&mBuf, 0);

    if (aMsg == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "missing_parameters");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    blobmsg_parse(joinerStartPolicy, JOINER_START_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (tb[JOINER_PSKD] == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "pskd_required");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    pskd = blobmsg_get_string(tb[JOINER_PSKD]);

    if (tb[JOINER_PROVISIONING_URL] != nullptr)
        provisioningUrl = blobmsg_get_string(tb[JOINER_PROVISIONING_URL]);
    if (tb[JOINER_VENDOR_NAME] != nullptr)
        vendorName = blobmsg_get_string(tb[JOINER_VENDOR_NAME]);
    if (tb[JOINER_VENDOR_MODEL] != nullptr)
        vendorModel = blobmsg_get_string(tb[JOINER_VENDOR_MODEL]);
    if (tb[JOINER_VENDOR_SW_VERSION] != nullptr)
        vendorSwVersion = blobmsg_get_string(tb[JOINER_VENDOR_SW_VERSION]);
    if (tb[JOINER_VENDOR_DATA] != nullptr)
        vendorData = blobmsg_get_string(tb[JOINER_VENDOR_DATA]);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otError error = otJoinerStart(instance, pskd, provisioningUrl,
                                  vendorName, vendorModel, vendorSwVersion, vendorData,
                                  &JoinerCallback, nullptr);

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Status", "joining");
        otbrLogInfo("otbr-agent: joiner started with pskd=%s", pskd);
        AddEventLog("joiner", "joiner_started");

        // Broadcast ubus event: joiner started
        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "joiner_started");
        blobmsg_add_string(&mEventBuf, "JoinerState",
                           otJoinerStateToString(otJoinerGetState(instance)));
        blobmsg_add_u64(&mEventBuf, "Timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.joiner", mEventBuf.head);
    }
    else
    {
        blobmsg_add_string(&mBuf, "Status", "failed");
        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));

        // Broadcast ubus event: joiner start failed
        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "joiner_start_failed");
        blobmsg_add_u32(&mEventBuf, "error_code", error);
        blobmsg_add_string(&mEventBuf, "error", otThreadErrorToString(error));
        blobmsg_add_u64(&mEventBuf, "Timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.joiner", mEventBuf.head);
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", error);
    blobmsg_add_string(&mBuf, "JoinerState", otJoinerStateToString(otJoinerGetState(instance)));

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: joinerstop =========================
// ubus call otbr-agent joinerstop
// Stops the Joiner role

int UbusAgentExt::HandleJoinerStop(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().JoinerStopDetail(aContext, aRequest);
}

int UbusAgentExt::JoinerStopDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otJoinerStop(instance);

    blobmsg_add_string(&mBuf, "Status", "stopped");
    blobmsg_add_string(&mBuf, "JoinerState", otJoinerStateToString(otJoinerGetState(instance)));
    blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);

    otbrLogInfo("otbr-agent: joiner stopped");
    AddEventLog("joiner", "joiner_stopped");

    // Broadcast ubus event: joiner stopped
    blob_buf_init(&mEventBuf, 0);
    blobmsg_add_string(&mEventBuf, "event", "joiner_stopped");
    blobmsg_add_string(&mEventBuf, "JoinerState",
                       otJoinerStateToString(otJoinerGetState(instance)));
    blobmsg_add_u64(&mEventBuf, "Timestamp", (uint64_t)time(nullptr));
    SendUbusEvent("otbr-agent.joiner", mEventBuf.head);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: joineradd ============================
// ubus call otbr-agent joineradd '{"pskd":"12345678", "eui64":"0011223344556677", "timeout":120}'
// ubus call otbr-agent joineradd '{"pskd":"12345678", "eui64":"*", "timeout":120}'
// ubus call otbr-agent joineradd '{"pskd":"ABCDEFGH", "discerner_value":12345, "discerner_length":64, "timeout":120}'
// Adds a Joiner entry to the Commissioner (requires commissioner to be active)

int UbusAgentExt::HandleJoinerAdd(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
                                  struct ubus_request_data *aRequest,
                                  const char               *aMethod,
                                  struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().JoinerAddDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::JoinerAddDetail(struct ubus_context      *aContext,
                                  struct ubus_request_data *aRequest,
                                  struct blob_attr         *aMsg)
{
    struct blob_attr *tb[JOINER_ADD_MAX];
    const char       *pskd  = nullptr;
    const char       *eui64 = nullptr;
    uint64_t          discernerValue = 0;
    uint32_t          discernerLength = 0;
    uint32_t          timeout = 0;
    bool              hasEui64 = false;
    bool              hasDiscerner = false;

    blob_buf_init(&mBuf, 0);

    if (aMsg == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "missing_parameters");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    blobmsg_parse(joinerAddPolicy, JOINER_ADD_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (tb[JOINER_ADD_PSKD] == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "pskd_required");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    pskd = blobmsg_get_string(tb[JOINER_ADD_PSKD]);

    if (tb[JOINER_ADD_EUI64] != nullptr)
    {
        eui64 = blobmsg_get_string(tb[JOINER_ADD_EUI64]);
        hasEui64 = true;
    }

    if (tb[JOINER_ADD_DISCERNER_VALUE] != nullptr && tb[JOINER_ADD_DISCERNER_LENGTH] != nullptr)
    {
        discernerValue = blobmsg_get_u64(tb[JOINER_ADD_DISCERNER_VALUE]);
        discernerLength = blobmsg_get_u32(tb[JOINER_ADD_DISCERNER_LENGTH]);
        hasDiscerner = true;
    }

    if (tb[JOINER_ADD_TIMEOUT] != nullptr)
    {
        timeout = blobmsg_get_u32(tb[JOINER_ADD_TIMEOUT]);
    }

    if (hasEui64 && hasDiscerner)
    {
        blobmsg_add_string(&mBuf, "Error", "cannot_specify_both_eui64_and_discerner");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otError error;

    if (hasEui64)
    {
        if (strcmp(eui64, "*") == 0)
        {
            error = otCommissionerAddJoiner(instance, nullptr, pskd, timeout);
        }
        else
        {
            otExtAddress extAddr;
            int len = strlen(eui64);
            if (len != OT_EXT_ADDRESS_SIZE * 2)
            {
                blobmsg_add_string(&mBuf, "Error", "invalid_eui64_length");
                blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
                mNcpThreadMutex->unlock();
                ubus_send_reply(aContext, aRequest, mBuf.head);
                return 0;
            }

            int parseResult = HexStringToBytes(eui64, extAddr.m8, OT_EXT_ADDRESS_SIZE);
            if (parseResult < 0)
            {
                blobmsg_add_string(&mBuf, "Error", "invalid_eui64_format");
                blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
                mNcpThreadMutex->unlock();
                ubus_send_reply(aContext, aRequest, mBuf.head);
                return 0;
            }

            error = otCommissionerAddJoiner(instance, &extAddr, pskd, timeout);
        }
    }
    else if (hasDiscerner)
    {
        if (discernerLength == 0 || discernerLength > OT_JOINER_MAX_DISCERNER_LENGTH)
        {
            blobmsg_add_string(&mBuf, "Error", "invalid_discerner_length");
            blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
            mNcpThreadMutex->unlock();
            ubus_send_reply(aContext, aRequest, mBuf.head);
            return 0;
        }

        otJoinerDiscerner discerner;
        discerner.mLength = static_cast<uint8_t>(discernerLength);
        discerner.mValue  = discernerValue;

        error = otCommissionerAddJoinerWithDiscerner(instance, &discerner, pskd, timeout);
    }
    else
    {
        error = otCommissionerAddJoiner(instance, nullptr, pskd, timeout);
    }

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Status", "joiner_added");
        otbrLogInfo("otbr-agent: commissioner joiner added with pskd=%s timeout=%u", pskd, timeout);
    }
    else
    {
        blobmsg_add_string(&mBuf, "Status", "failed");
        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", error);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: joinerremove =========================
// ubus call otbr-agent joinerremove '{"eui64":"0011223344556677"}'
// ubus call otbr-agent joinerremove '{"eui64":"*"}'
// ubus call otbr-agent joinerremove '{"discerner_value":12345, "discerner_length":64}'
// Removes a Joiner entry from the Commissioner

int UbusAgentExt::HandleJoinerRemove(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
                                     struct ubus_request_data *aRequest,
                                     const char               *aMethod,
                                     struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().JoinerRemoveDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::JoinerRemoveDetail(struct ubus_context      *aContext,
                                     struct ubus_request_data *aRequest,
                                     struct blob_attr         *aMsg)
{
    struct blob_attr *tb[JOINER_REMOVE_MAX];
    const char       *eui64 = nullptr;
    uint64_t          discernerValue = 0;
    uint32_t          discernerLength = 0;
    bool              hasEui64 = false;
    bool              hasDiscerner = false;

    blob_buf_init(&mBuf, 0);

    if (aMsg == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "missing_parameters");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    blobmsg_parse(joinerRemovePolicy, JOINER_REMOVE_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (tb[JOINER_REMOVE_EUI64] != nullptr)
    {
        eui64 = blobmsg_get_string(tb[JOINER_REMOVE_EUI64]);
        hasEui64 = true;
    }

    if (tb[JOINER_REMOVE_DISCERNER_VALUE] != nullptr && tb[JOINER_REMOVE_DISCERNER_LENGTH] != nullptr)
    {
        discernerValue = blobmsg_get_u64(tb[JOINER_REMOVE_DISCERNER_VALUE]);
        discernerLength = blobmsg_get_u32(tb[JOINER_REMOVE_DISCERNER_LENGTH]);
        hasDiscerner = true;
    }

    if (hasEui64 && hasDiscerner)
    {
        blobmsg_add_string(&mBuf, "Error", "cannot_specify_both_eui64_and_discerner");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otError error;

    if (hasEui64)
    {
        if (strcmp(eui64, "*") == 0)
        {
            error = otCommissionerRemoveJoiner(instance, nullptr);
        }
        else
        {
            otExtAddress extAddr;
            int len = strlen(eui64);
            if (len != OT_EXT_ADDRESS_SIZE * 2)
            {
                blobmsg_add_string(&mBuf, "Error", "invalid_eui64_length");
                blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
                mNcpThreadMutex->unlock();
                ubus_send_reply(aContext, aRequest, mBuf.head);
                return 0;
            }

            int parseResult = HexStringToBytes(eui64, extAddr.m8, OT_EXT_ADDRESS_SIZE);
            if (parseResult < 0)
            {
                blobmsg_add_string(&mBuf, "Error", "invalid_eui64_format");
                blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
                mNcpThreadMutex->unlock();
                ubus_send_reply(aContext, aRequest, mBuf.head);
                return 0;
            }

            error = otCommissionerRemoveJoiner(instance, &extAddr);
        }
    }
    else if (hasDiscerner)
    {
        if (discernerLength == 0 || discernerLength > OT_JOINER_MAX_DISCERNER_LENGTH)
        {
            blobmsg_add_string(&mBuf, "Error", "invalid_discerner_length");
            blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
            mNcpThreadMutex->unlock();
            ubus_send_reply(aContext, aRequest, mBuf.head);
            return 0;
        }

        otJoinerDiscerner discerner;
        discerner.mLength = static_cast<uint8_t>(discernerLength);
        discerner.mValue  = discernerValue;

        error = otCommissionerRemoveJoinerWithDiscerner(instance, &discerner);
    }
    else
    {
        error = otCommissionerRemoveJoiner(instance, nullptr);
    }

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Status", "joiner_removed");
        otbrLogInfo("otbr-agent: commissioner joiner removed");
    }
    else
    {
        blobmsg_add_string(&mBuf, "Status", "failed");
        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", error);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: getaddrs ===========================
// ubus call otbr-agent getaddrs
// Returns all unicast IPv6 addresses

int UbusAgentExt::HandleGetAddrs(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().GetAddrsDetail(aContext, aRequest);
}

int UbusAgentExt::GetAddrsDetail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest)
{
    char addrStr[OT_IP6_ADDRESS_STRING_SIZE];

    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    void *addrArray = blobmsg_open_array(&mBuf, "Addrs");

    const otNetifAddress *addr = otIp6GetUnicastAddresses(instance);
    while (addr != nullptr)
    {
        void *addrEntry = blobmsg_open_table(&mBuf, nullptr);

        otIp6AddressToString(&addr->mAddress, addrStr, sizeof(addrStr));
        blobmsg_add_string(&mBuf, "Address", addrStr);
        blobmsg_add_u32(&mBuf, "PrefixLength", addr->mPrefixLength);
        blobmsg_add_u8(&mBuf, "Preferred", addr->mPreferred);
        blobmsg_add_u8(&mBuf, "Valid", addr->mValid);

        const char *origin;
        switch (addr->mAddressOrigin)
        {
        case OT_ADDRESS_ORIGIN_THREAD:
            origin = "thread";
            break;
        case OT_ADDRESS_ORIGIN_SLAAC:
            origin = "slaac";
            break;
        case OT_ADDRESS_ORIGIN_DHCPV6:
            origin = "dhcpv6";
            break;
        case OT_ADDRESS_ORIGIN_MANUAL:
            origin = "manual";
            break;
        default:
            origin = "unknown";
            break;
        }
        blobmsg_add_string(&mBuf, "Origin", origin);

        blobmsg_close_table(&mBuf, addrEntry);
        addr = addr->mNext;
    }

    blobmsg_close_array(&mBuf, addrArray);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: dataset ============================
// ubus call otbr-agent dataset '{"type":"active"}'
// ubus call otbr-agent dataset '{"type":"pending"}'
// Returns the dataset in TLV hex string

int UbusAgentExt::HandleDataset(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
                                struct ubus_request_data *aRequest,
                                const char               *aMethod,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().DatasetDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::DatasetDetail(struct ubus_context      *aContext,
                                struct ubus_request_data *aRequest,
                                struct blob_attr         *aMsg)
{
    struct blob_attr *tb[DATASET_MAX];
    const char       *type = "active";

    blob_buf_init(&mBuf, 0);

    if (aMsg != nullptr)
    {
        blobmsg_parse(datasetPolicy, DATASET_MAX, tb, blob_data(aMsg), blob_len(aMsg));
        if (tb[DATASET_TYPE] != nullptr)
        {
            type = blobmsg_get_string(tb[DATASET_TYPE]);
        }
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otOperationalDatasetTlvs datasetTlvs;
    otError                  error;

    if (strcmp(type, "pending") == 0)
    {
        error = otDatasetGetPendingTlvs(instance, &datasetTlvs);
    }
    else
    {
        error = otDatasetGetActiveTlvs(instance, &datasetTlvs);
    }

    if (error == OT_ERROR_NONE)
    {
        char tlvHex[OT_OPERATIONAL_DATASET_MAX_LENGTH * 2 + 1] = "";
        OutputBytes(datasetTlvs.mTlvs, datasetTlvs.mLength, tlvHex);

        blobmsg_add_string(&mBuf, "Type", type);
        blobmsg_add_string(&mBuf, "DatasetTlvs", tlvHex);
        blobmsg_add_u32(&mBuf, "DatasetLen", datasetTlvs.mLength);

        // Also parse the dataset for human-readable fields
        otOperationalDataset dataset;
        otError parseError;

        if (strcmp(type, "pending") == 0)
        {
            parseError = otDatasetGetPending(instance, &dataset);
        }
        else
        {
            parseError = otDatasetGetActive(instance, &dataset);
        }

        if (parseError == OT_ERROR_NONE)
        {
            void *parsed = blobmsg_open_table(&mBuf, "Parsed");

            if (dataset.mComponents.mIsNetworkNamePresent)
            {
                blobmsg_add_string(&mBuf, "NetworkName", dataset.mNetworkName.m8);
            }
            if (dataset.mComponents.mIsChannelPresent)
            {
                blobmsg_add_u32(&mBuf, "Channel", dataset.mChannel);
            }
            if (dataset.mComponents.mIsPanIdPresent)
            {
                char panidstr[12];
                snprintf(panidstr, sizeof(panidstr), "0x%04x", dataset.mPanId);
                blobmsg_add_string(&mBuf, "PanId", panidstr);
            }
            if (dataset.mComponents.mIsExtendedPanIdPresent)
            {
                char xpanidstr[OT_EXT_PAN_ID_SIZE * 2 + 1] = "";
                OutputBytes(dataset.mExtendedPanId.m8, OT_EXT_PAN_ID_SIZE, xpanidstr);
                blobmsg_add_string(&mBuf, "ExtPanId", xpanidstr);
            }
            if (dataset.mComponents.mIsNetworkKeyPresent)
            {
                char nkstr[OT_NETWORK_KEY_SIZE * 2 + 1] = "";
                OutputBytes(dataset.mNetworkKey.m8, OT_NETWORK_KEY_SIZE, nkstr);
                blobmsg_add_string(&mBuf, "NetworkKey", nkstr);
            }

            blobmsg_close_table(&mBuf, parsed);
        }
    }
    else
    {
        blobmsg_add_string(&mBuf, "Error", "dataset not found");
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", error);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: topology ===========================
// ubus call otbr-agent topology
// Returns all routers as an array of objects, each containing its
// children and neighbor nodes. Provides a NETWORK-WIDE view.
//   - Self router: children from local child table (full info),
//     neighbors from neighbor table.
//   - Remote routers: children inferred from EID cache.

int UbusAgentExt::HandleTopology(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().TopologyDetail(aContext, aRequest);
}

int UbusAgentExt::TopologyDetail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest)
{
    char extAddrStr[OT_EXT_ADDRESS_SIZE * 2 + 1] = "";

    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance  *instance   = mController->GetInstance();
    otDeviceRole role       = otThreadGetDeviceRole(instance);

    if (role != OT_DEVICE_ROLE_CHILD && role != OT_DEVICE_ROLE_ROUTER && role != OT_DEVICE_ROLE_LEADER)
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *routerArray = blobmsg_open_array(&mBuf, "Routers");
        blobmsg_close_array(&mBuf, routerArray);
        blobmsg_add_u32(&mBuf, "RouterCount", 0);
        mNcpThreadMutex->unlock();
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    uint16_t selfRloc16 = otThreadGetRloc16(instance);

    blobmsg_add_string(&mBuf, "Role", RoleToString(role));
    AddRloc16ToBlob(&mBuf, "SelfRloc16", selfRloc16);

    // ---- Pre-collect EID cache: group child entries by parent router RLOC16 ----
    // Child RLOC16 has non-zero lower 10 bits; parent = RLOC16 & 0xFC00.
    struct EidChild
    {
        uint16_t    rloc16;
        char        target[OT_IP6_ADDRESS_STRING_SIZE];
        const char *state;
    };
    std::map<uint16_t, std::vector<EidChild>> eidChildrenByRouter;

    {
        otCacheEntryIterator eidIter;
        otCacheEntryInfo     eidEntry;
        memset(&eidIter, 0, sizeof(eidIter));

        while (otThreadGetNextCacheEntry(instance, &eidEntry, &eidIter) == OT_ERROR_NONE)
        {
            uint16_t childRloc  = eidEntry.mRloc16;
            uint16_t parentRloc = childRloc & 0xFC00;
            uint16_t childId    = childRloc & 0x03FF;

            if (childId != 0)
            {
                EidChild ec;
                ec.rloc16 = childRloc;
                otIp6AddressToString(&eidEntry.mTarget, ec.target, sizeof(ec.target));
                switch (eidEntry.mState)
                {
                case OT_CACHE_ENTRY_STATE_CACHED:
                    ec.state = "cached";
                    break;
                case OT_CACHE_ENTRY_STATE_SNOOPED:
                    ec.state = "snooped";
                    break;
                case OT_CACHE_ENTRY_STATE_QUERY:
                    ec.state = "query";
                    break;
                case OT_CACHE_ENTRY_STATE_RETRY_QUERY:
                    ec.state = "retry_query";
                    break;
                default:
                    ec.state = "unknown";
                    break;
                }
                eidChildrenByRouter[parentRloc].push_back(ec);
            }
        }
    }

    // ---- Enumerate all routers via Router ID table ----
    uint8_t maxRouterId = otThreadGetMaxRouterId(instance);
    void   *routerArray = blobmsg_open_array(&mBuf, "Routers");
    int     routerCount = 0;

    for (uint8_t routerId = 0; routerId <= maxRouterId; routerId++)
    {
        otRouterInfo routerInfo;
        if (otThreadGetRouterInfo(instance, routerId, &routerInfo) != OT_ERROR_NONE)
        {
            continue;
        }
        if (!routerInfo.mAllocated)
        {
            continue;
        }

        void *routerEntry = blobmsg_open_table(&mBuf, nullptr);

        blobmsg_add_u32(&mBuf, "RouterId", routerInfo.mRouterId);
        AddRloc16ToBlob(&mBuf, "Rloc16", routerInfo.mRloc16);
        OutputBytes(routerInfo.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
        blobmsg_add_string(&mBuf, "ExtAddr", extAddrStr);
        blobmsg_add_u32(&mBuf, "NextHop", routerInfo.mNextHop);
        blobmsg_add_u32(&mBuf, "PathCost", routerInfo.mPathCost);
        blobmsg_add_u32(&mBuf, "LinkQualityIn", routerInfo.mLinkQualityIn);
        blobmsg_add_u32(&mBuf, "LinkQualityOut", routerInfo.mLinkQualityOut);
        blobmsg_add_u32(&mBuf, "Age", routerInfo.mAge);
        blobmsg_add_u8(&mBuf, "LinkEstablished", routerInfo.mLinkEstablished);
        blobmsg_add_u32(&mBuf, "Version", routerInfo.mVersion);

        bool isSelf = (routerInfo.mRloc16 == selfRloc16);
        blobmsg_add_u8(&mBuf, "IsSelf", isSelf);

        // ---- Children under this router ----
        void *childArray = blobmsg_open_array(&mBuf, "Children");
        int   childCount = 0;

        if (isSelf)
        {
            // Full child info from local child table
            uint16_t maxChildren = otThreadGetMaxAllowedChildren(instance);
            for (uint16_t childIdx = 0; childIdx < maxChildren; childIdx++)
            {
                otChildInfo childInfo;
                if (otThreadGetChildInfoByIndex(instance, childIdx, &childInfo) != OT_ERROR_NONE)
                {
                    continue;
                }

                void *childEntry = blobmsg_open_table(&mBuf, nullptr);

                AddRloc16ToBlob(&mBuf, "Rloc16", childInfo.mRloc16);
                blobmsg_add_u32(&mBuf, "ChildId", childInfo.mChildId);
                OutputBytes(childInfo.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
                blobmsg_add_string(&mBuf, "ExtAddr", extAddrStr);
                blobmsg_add_u32(&mBuf, "Timeout", childInfo.mTimeout);
                blobmsg_add_u32(&mBuf, "Age", childInfo.mAge);
                blobmsg_add_u32(&mBuf, "LinkQualityIn", childInfo.mLinkQualityIn);
                blobmsg_add_u32(&mBuf, "AverageRssi", (uint32_t)(int32_t)childInfo.mAverageRssi);
                blobmsg_add_u32(&mBuf, "LastRssi", (uint32_t)(int32_t)childInfo.mLastRssi);
                blobmsg_add_u8(&mBuf, "RxOnWhenIdle", childInfo.mRxOnWhenIdle);
                blobmsg_add_u8(&mBuf, "FullThreadDevice", childInfo.mFullThreadDevice);
                blobmsg_add_u8(&mBuf, "FullNetworkData", childInfo.mFullNetworkData);
                blobmsg_add_u8(&mBuf, "IsStateRestoring", childInfo.mIsStateRestoring);
                blobmsg_add_u32(&mBuf, "Version", childInfo.mVersion);

                // Enumerate child's IPv6 addresses
                void                     *addrArr  = blobmsg_open_array(&mBuf, "Ip6Addrs");
                otChildIp6AddressIterator  addrIter = OT_CHILD_IP6_ADDRESS_ITERATOR_INIT;
                otIp6Address               ip6Addr;
                char                       addrStr[OT_IP6_ADDRESS_STRING_SIZE];

                while (otThreadGetChildNextIp6Address(instance, childIdx, &addrIter, &ip6Addr) == OT_ERROR_NONE)
                {
                    otIp6AddressToString(&ip6Addr, addrStr, sizeof(addrStr));
                    blobmsg_add_string(&mBuf, nullptr, addrStr);
                }
                blobmsg_close_array(&mBuf, addrArr);

                blobmsg_close_table(&mBuf, childEntry);
                childCount++;
            }
        }
        else
        {
            // Remote router: infer children from EID cache
            auto it = eidChildrenByRouter.find(routerInfo.mRloc16);
            if (it != eidChildrenByRouter.end())
            {
                for (const auto &ec : it->second)
                {
                    void *childEntry = blobmsg_open_table(&mBuf, nullptr);

                    AddRloc16ToBlob(&mBuf, "Rloc16", ec.rloc16);
                    blobmsg_add_u32(&mBuf, "ChildId", ec.rloc16 & 0x03FF);
                    blobmsg_add_string(&mBuf, "Target", ec.target);
                    blobmsg_add_string(&mBuf, "State", ec.state);

                    blobmsg_close_table(&mBuf, childEntry);
                    childCount++;
                }
            }
        }

        blobmsg_close_array(&mBuf, childArray);
        blobmsg_add_u32(&mBuf, "ChildCount", childCount);

        // ---- Neighbors of this router ----
        void *neighborArray = blobmsg_open_array(&mBuf, "Neighbors");
        int   neighborCount = 0;

        if (isSelf)
        {
            // Full neighbor info from local neighbor table
            otNeighborInfoIterator nbrIter = OT_NEIGHBOR_INFO_ITERATOR_INIT;
            otNeighborInfo         nbrInfo;

            while (otThreadGetNextNeighborInfo(instance, &nbrIter, &nbrInfo) == OT_ERROR_NONE)
            {
                void *nbrEntry = blobmsg_open_table(&mBuf, nullptr);

                OutputBytes(nbrInfo.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
                blobmsg_add_string(&mBuf, "ExtAddr", extAddrStr);
                AddRloc16ToBlob(&mBuf, "Rloc16", nbrInfo.mRloc16);
                blobmsg_add_u32(&mBuf, "Age", nbrInfo.mAge);
                blobmsg_add_u32(&mBuf, "LinkQualityIn", nbrInfo.mLinkQualityIn);
                blobmsg_add_u32(&mBuf, "AverageRssi", (uint32_t)(int32_t)nbrInfo.mAverageRssi);
                blobmsg_add_u32(&mBuf, "LastRssi", (uint32_t)(int32_t)nbrInfo.mLastRssi);
                blobmsg_add_u32(&mBuf, "FrameErrorRate", nbrInfo.mFrameErrorRate);
                blobmsg_add_u32(&mBuf, "MessageErrorRate", nbrInfo.mMessageErrorRate);
                blobmsg_add_u8(&mBuf, "RxOnWhenIdle", nbrInfo.mRxOnWhenIdle);
                blobmsg_add_u8(&mBuf, "FullThreadDevice", nbrInfo.mFullThreadDevice);
                blobmsg_add_u8(&mBuf, "FullNetworkData", nbrInfo.mFullNetworkData);
                blobmsg_add_u8(&mBuf, "IsChild", nbrInfo.mIsChild);
                blobmsg_add_u32(&mBuf, "Version", nbrInfo.mVersion);

                blobmsg_close_table(&mBuf, nbrEntry);
                neighborCount++;
            }
        }

        blobmsg_close_array(&mBuf, neighborArray);
        blobmsg_add_u32(&mBuf, "NeighborCount", neighborCount);

        blobmsg_close_table(&mBuf, routerEntry);
        routerCount++;
    }

    blobmsg_close_array(&mBuf, routerArray);
    blobmsg_add_u32(&mBuf, "RouterCount", routerCount);
    blobmsg_add_u32(&mBuf, "RouterIdSequence", otThreadGetRouterIdSequence(instance));

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ============== Topology Scan (Network-wide) ==================
// Called from HandleStateChanged when network data or role changes.
// Compares current router/child tables with previous snapshot to
// detect additions and removals network-wide.
// NOTE: mNcpThreadMutex is already held by the caller.

void UbusAgentExt::ScanNetworkTopology(void)
{
    otInstance *instance = mController->GetInstance();
    char extAddrStr[OT_EXT_ADDRESS_SIZE * 2 + 1] = "";
    char rloc16str[8]                             = "";

    // ---- Scan all routers by Router ID ----
    uint8_t maxRouterId = otThreadGetMaxRouterId(instance);
    std::map<uint8_t, RouterSnapshot> currentRouters;

    for (uint8_t routerId = 0; routerId <= maxRouterId; routerId++)
    {
        otRouterInfo routerInfo;
        if (otThreadGetRouterInfo(instance, routerId, &routerInfo) != OT_ERROR_NONE)
        {
            continue;
        }
        if (!routerInfo.mAllocated)
        {
            continue;
        }

        RouterSnapshot snap;
        snap.mRouterId        = routerInfo.mRouterId;
        snap.mRloc16          = routerInfo.mRloc16;
        snap.mExtAddress      = routerInfo.mExtAddress;
        snap.mPathCost        = routerInfo.mPathCost;
        snap.mLinkEstablished = routerInfo.mLinkEstablished;

        currentRouters[routerId] = snap;
    }

    // ---- Scan children (only meaningful when we are router/leader) ----
    std::map<uint16_t, ChildSnapshot> currentChildren;
    otDeviceRole myRole = otThreadGetDeviceRole(instance);

    if (myRole == OT_DEVICE_ROLE_ROUTER || myRole == OT_DEVICE_ROLE_LEADER)
    {
        uint16_t maxChildren = otThreadGetMaxAllowedChildren(instance);
        for (uint16_t childIdx = 0; childIdx < maxChildren; childIdx++)
        {
            otChildInfo childInfo;
            if (otThreadGetChildInfoByIndex(instance, childIdx, &childInfo) != OT_ERROR_NONE)
            {
                continue;
            }

            ChildSnapshot snap;
            snap.mRloc16          = childInfo.mRloc16;
            snap.mChildId         = childInfo.mChildId;
            snap.mExtAddress      = childInfo.mExtAddress;
            snap.mRxOnWhenIdle    = childInfo.mRxOnWhenIdle;
            snap.mFullThreadDevice = childInfo.mFullThreadDevice;

            currentChildren[childInfo.mRloc16] = snap;
        }
    }

    // Skip diff on first scan (just initialize the snapshot)
    if (!mTopologyInitialized)
    {
        mKnownRouters  = currentRouters;
        mKnownChildren = currentChildren;
        mTopologyInitialized = true;

        otbrLogInfo("otbr-agent: topology initialized with %u routers, %u children",
                    (unsigned)currentRouters.size(), (unsigned)currentChildren.size());
        return;
    }

    // ---- Detect added routers ----
    for (const auto &kv : currentRouters)
    {
        uint8_t id = kv.first;
        const RouterSnapshot &snap = kv.second;

        if (mKnownRouters.find(id) == mKnownRouters.end())
        {
            OutputBytes(snap.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
            snprintf(rloc16str, sizeof(rloc16str), "0x%04x", snap.mRloc16);

            otbrLogInfo("otbr-agent: [topology] router added: id=%u rloc16=%s ext=%s",
                        id, rloc16str, extAddrStr);

            std::string detail = std::string("router_added id=") + std::to_string(id) +
                                 " rloc16=" + rloc16str + " ext=" + extAddrStr;
            AddEventLog("topology", detail);

            blob_buf_init(&mEventBuf, 0);
            blobmsg_add_string(&mEventBuf, "event", "router_added");
            blobmsg_add_u32(&mEventBuf, "router_id", id);
            blobmsg_add_string(&mEventBuf, "rloc16", rloc16str);
            blobmsg_add_string(&mEventBuf, "extaddr", extAddrStr);
            blobmsg_add_u32(&mEventBuf, "path_cost", snap.mPathCost);
            blobmsg_add_u8(&mEventBuf, "link_established", snap.mLinkEstablished);
            blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
            SendUbusEvent("otbr-agent.topology", mEventBuf.head);
        }
    }

    // ---- Detect removed routers ----
    for (const auto &kv : mKnownRouters)
    {
        uint8_t id = kv.first;
        const RouterSnapshot &snap = kv.second;

        if (currentRouters.find(id) == currentRouters.end())
        {
            OutputBytes(snap.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
            snprintf(rloc16str, sizeof(rloc16str), "0x%04x", snap.mRloc16);

            otbrLogInfo("otbr-agent: [topology] router removed: id=%u rloc16=%s ext=%s",
                        id, rloc16str, extAddrStr);

            std::string detail = std::string("router_removed id=") + std::to_string(id) +
                                 " rloc16=" + rloc16str + " ext=" + extAddrStr;
            AddEventLog("topology", detail);

            blob_buf_init(&mEventBuf, 0);
            blobmsg_add_string(&mEventBuf, "event", "router_removed");
            blobmsg_add_u32(&mEventBuf, "router_id", id);
            blobmsg_add_string(&mEventBuf, "rloc16", rloc16str);
            blobmsg_add_string(&mEventBuf, "extaddr", extAddrStr);
            blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
            SendUbusEvent("otbr-agent.topology", mEventBuf.head);
        }
    }

    // ---- Detect added children ----
    for (const auto &kv : currentChildren)
    {
        uint16_t rloc = kv.first;
        const ChildSnapshot &snap = kv.second;

        if (mKnownChildren.find(rloc) == mKnownChildren.end())
        {
            OutputBytes(snap.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
            snprintf(rloc16str, sizeof(rloc16str), "0x%04x", snap.mRloc16);

            otbrLogInfo("otbr-agent: [topology] child added: rloc16=%s ext=%s childid=%u",
                        rloc16str, extAddrStr, snap.mChildId);

            std::string detail = std::string("child_added rloc16=") + rloc16str +
                                 " ext=" + extAddrStr + " childid=" + std::to_string(snap.mChildId);
            AddEventLog("topology", detail);

            blob_buf_init(&mEventBuf, 0);
            blobmsg_add_string(&mEventBuf, "event", "child_added");
            blobmsg_add_string(&mEventBuf, "rloc16", rloc16str);
            blobmsg_add_string(&mEventBuf, "extaddr", extAddrStr);
            blobmsg_add_u32(&mEventBuf, "child_id", snap.mChildId);
            blobmsg_add_u8(&mEventBuf, "rx_on_when_idle", snap.mRxOnWhenIdle);
            blobmsg_add_u8(&mEventBuf, "full_thread_device", snap.mFullThreadDevice);
            blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
            SendUbusEvent("otbr-agent.topology", mEventBuf.head);
        }
    }

    // ---- Detect removed children ----
    for (const auto &kv : mKnownChildren)
    {
        uint16_t rloc = kv.first;
        const ChildSnapshot &snap = kv.second;

        if (currentChildren.find(rloc) == currentChildren.end())
        {
            OutputBytes(snap.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
            snprintf(rloc16str, sizeof(rloc16str), "0x%04x", snap.mRloc16);

            otbrLogInfo("otbr-agent: [topology] child removed: rloc16=%s ext=%s childid=%u",
                        rloc16str, extAddrStr, snap.mChildId);

            std::string detail = std::string("child_removed rloc16=") + rloc16str +
                                 " ext=" + extAddrStr + " childid=" + std::to_string(snap.mChildId);
            AddEventLog("topology", detail);

            blob_buf_init(&mEventBuf, 0);
            blobmsg_add_string(&mEventBuf, "event", "child_removed");
            blobmsg_add_string(&mEventBuf, "rloc16", rloc16str);
            blobmsg_add_string(&mEventBuf, "extaddr", extAddrStr);
            blobmsg_add_u32(&mEventBuf, "child_id", snap.mChildId);
            blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
            SendUbusEvent("otbr-agent.topology", mEventBuf.head);
        }
    }

    // Update snapshots
    mKnownRouters  = currentRouters;
    mKnownChildren = currentChildren;
}

// ============== State Changed Callback ========================
// Called from the NCP main loop thread via AddThreadStateChangedCallback().
// We decode the flags, log events, and broadcast ubus events.

void UbusAgentExt::HandleStateChanged(otChangedFlags aFlags)
{
    // NOTE: This is called from the NCP thread context.
    // mNcpThreadMutex is already held by the caller (ControllerOpenThread).
    otInstance  *instance = mController->GetInstance();
    otDeviceRole newRole  = otThreadGetDeviceRole(instance);

    // --- Role change ---
    if (aFlags & OT_CHANGED_THREAD_ROLE)
    {
        const char *oldRoleStr = RoleToString(mLastRole);
        const char *newRoleStr = RoleToString(newRole);

        otbrLogInfo("otbr-agent: role changed: %s -> %s", oldRoleStr, newRoleStr);

        // Build event detail
        std::string detail = std::string("role:") + oldRoleStr + "->" + newRoleStr;
        AddEventLog("state", detail);

        // Broadcast ubus event
        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "role_changed");
        blobmsg_add_string(&mEventBuf, "old_role", oldRoleStr);
        blobmsg_add_string(&mEventBuf, "new_role", newRoleStr);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);

        mLastRole = newRole;
    }

    // --- Network data changed ---
    if (aFlags & OT_CHANGED_THREAD_NETDATA)
    {
        otbrLogInfo("otbr-agent: network data changed");
        AddEventLog("state", "network_data_changed");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "network_data_changed");
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Child added/removed (state change level) ---
    if (aFlags & OT_CHANGED_THREAD_CHILD_ADDED)
    {
        otbrLogInfo("otbr-agent: child added (state flag)");
        AddEventLog("state", "child_added");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "child_added");
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }
    if (aFlags & OT_CHANGED_THREAD_CHILD_REMOVED)
    {
        otbrLogInfo("otbr-agent: child removed (state flag)");
        AddEventLog("state", "child_removed");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "child_removed");
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Partition ID changed ---
    if (aFlags & OT_CHANGED_THREAD_PARTITION_ID)
    {
        uint32_t partitionId = otThreadGetPartitionId(instance);
        otbrLogInfo("otbr-agent: partition id changed to %u", partitionId);

        char buf[32];
        snprintf(buf, sizeof(buf), "partition_id:%u", partitionId);
        AddEventLog("state", buf);

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "partition_id_changed");
        blobmsg_add_u32(&mEventBuf, "partition_id", partitionId);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Network name changed ---
    if (aFlags & OT_CHANGED_THREAD_NETWORK_NAME)
    {
        const char *name = otThreadGetNetworkName(instance);
        otbrLogInfo("otbr-agent: network name changed to %s", name);

        std::string detail = std::string("network_name:") + name;
        AddEventLog("state", detail);

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "network_name_changed");
        blobmsg_add_string(&mEventBuf, "network_name", name);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Channel changed ---
    if (aFlags & OT_CHANGED_THREAD_CHANNEL)
    {
        uint8_t channel = otLinkGetChannel(instance);
        otbrLogInfo("otbr-agent: channel changed to %u", channel);

        char buf[32];
        snprintf(buf, sizeof(buf), "channel:%u", channel);
        AddEventLog("state", buf);

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "channel_changed");
        blobmsg_add_u32(&mEventBuf, "channel", channel);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- PAN ID changed ---
    if (aFlags & OT_CHANGED_THREAD_PANID)
    {
        otPanId panid = otLinkGetPanId(instance);
        otbrLogInfo("otbr-agent: PAN ID changed to 0x%04x", panid);

        char buf[32];
        snprintf(buf, sizeof(buf), "panid:0x%04x", panid);
        AddEventLog("state", buf);

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "panid_changed");
        char panidstr[12];
        snprintf(panidstr, sizeof(panidstr), "0x%04x", panid);
        blobmsg_add_string(&mEventBuf, "panid", panidstr);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Active Dataset changed ---
    if (aFlags & OT_CHANGED_ACTIVE_DATASET)
    {
        otbrLogInfo("otbr-agent: active dataset changed");
        AddEventLog("state", "active_dataset_changed");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "active_dataset_changed");
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Pending Dataset changed ---
    if (aFlags & OT_CHANGED_PENDING_DATASET)
    {
        otbrLogInfo("otbr-agent: pending dataset changed");
        AddEventLog("state", "pending_dataset_changed");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "pending_dataset_changed");
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- Network Key changed ---
    if (aFlags & OT_CHANGED_NETWORK_KEY)
    {
        otbrLogInfo("otbr-agent: network key changed");
        AddEventLog("state", "network_key_changed");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "network_key_changed");
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }

    // --- IPv6 address added/removed ---
    if (aFlags & OT_CHANGED_IP6_ADDRESS_ADDED)
    {
        AddEventLog("state", "ipv6_address_added");
    }
    if (aFlags & OT_CHANGED_IP6_ADDRESS_REMOVED)
    {
        AddEventLog("state", "ipv6_address_removed");
    }

    // --- Thread interface state changed ---
    if (aFlags & OT_CHANGED_THREAD_NETIF_STATE)
    {
        bool isUp = otIp6IsEnabled(instance);
        otbrLogInfo("otbr-agent: netif state changed, ip6 enabled=%d", isUp);

        AddEventLog("state", isUp ? "netif_up" : "netif_down");

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", "netif_state_changed");
        blobmsg_add_u8(&mEventBuf, "ip6_enabled", isUp);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.state", mEventBuf.head);
    }
}

// ============== Neighbor Table Callback =======================
// Called from OpenThread stack context.
// Provides detailed info about child/router add/remove events.

void UbusAgentExt::HandleNeighborTableChanged(otNeighborTableEvent             aEvent,
                                              const otNeighborTableEntryInfo  *aEntryInfo)
{
    if (sAgentInstance != nullptr)
    {
        sAgentInstance->HandleNeighborTableChangedDetail(aEvent, aEntryInfo);
    }
}

void UbusAgentExt::HandleNeighborTableChangedDetail(otNeighborTableEvent             aEvent,
                                                     const otNeighborTableEntryInfo  *aEntryInfo)
{
    const char *eventStr = NeighborEventToString(aEvent);
    char        extAddrStr[OT_EXT_ADDRESS_SIZE * 2 + 1] = "";
    char        rloc16str[8]                             = "";

    bool isChild = (aEvent == OT_NEIGHBOR_TABLE_EVENT_CHILD_ADDED ||
                    aEvent == OT_NEIGHBOR_TABLE_EVENT_CHILD_REMOVED ||
                    aEvent == OT_NEIGHBOR_TABLE_EVENT_CHILD_MODE_CHANGED);

    if (isChild)
    {
        const otChildInfo &child = aEntryInfo->mInfo.mChild;
        OutputBytes(child.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
        snprintf(rloc16str, sizeof(rloc16str), "0x%04x", child.mRloc16);

        otbrLogInfo("otbr-agent: neighbor event=%s type=child rloc16=%s extaddr=%s",
                    eventStr, rloc16str, extAddrStr);

        // Build event log detail
        std::string detail = std::string(eventStr) + " child rloc16=" + rloc16str + " ext=" + extAddrStr;
        AddEventLog("neighbor", detail);

        // Broadcast ubus event
        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", eventStr);
        blobmsg_add_string(&mEventBuf, "type", "child");
        blobmsg_add_string(&mEventBuf, "rloc16", rloc16str);
        blobmsg_add_string(&mEventBuf, "extaddr", extAddrStr);
        blobmsg_add_u32(&mEventBuf, "child_id", child.mChildId);
        blobmsg_add_u8(&mEventBuf, "rx_on_when_idle", child.mRxOnWhenIdle);
        blobmsg_add_u8(&mEventBuf, "full_thread_device", child.mFullThreadDevice);
        blobmsg_add_u8(&mEventBuf, "full_network_data", child.mFullNetworkData);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.neighbor", mEventBuf.head);
    }
    else
    {
        // Router event
        const otNeighborInfo &router = aEntryInfo->mInfo.mRouter;
        OutputBytes(router.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
        snprintf(rloc16str, sizeof(rloc16str), "0x%04x", router.mRloc16);

        otbrLogInfo("otbr-agent: neighbor event=%s type=router rloc16=%s extaddr=%s",
                    eventStr, rloc16str, extAddrStr);

        std::string detail = std::string(eventStr) + " router rloc16=" + rloc16str + " ext=" + extAddrStr;
        AddEventLog("neighbor", detail);

        blob_buf_init(&mEventBuf, 0);
        blobmsg_add_string(&mEventBuf, "event", eventStr);
        blobmsg_add_string(&mEventBuf, "type", "router");
        blobmsg_add_string(&mEventBuf, "rloc16", rloc16str);
        blobmsg_add_string(&mEventBuf, "extaddr", extAddrStr);
        blobmsg_add_u32(&mEventBuf, "link_quality_in", router.mLinkQualityIn);
        blobmsg_add_u32(&mEventBuf, "average_rssi", (uint32_t)(int32_t)router.mAverageRssi);
        blobmsg_add_u32(&mEventBuf, "last_rssi", (uint32_t)(int32_t)router.mLastRssi);
        blobmsg_add_u8(&mEventBuf, "rx_on_when_idle", router.mRxOnWhenIdle);
        blobmsg_add_u8(&mEventBuf, "full_thread_device", router.mFullThreadDevice);
        blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
        SendUbusEvent("otbr-agent.neighbor", mEventBuf.head);
    }
}

// ================ Handler: getevents ==========================
// ubus call otbr-agent getevents
// ubus call otbr-agent getevents '{"count":50}'
// Returns recent event log entries

int UbusAgentExt::HandleGetEvents(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
                                  struct ubus_request_data *aRequest,
                                  const char               *aMethod,
                                  struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().GetEventsDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::GetEventsDetail(struct ubus_context      *aContext,
                                  struct ubus_request_data *aRequest,
                                  struct blob_attr         *aMsg)
{
    struct blob_attr *tb[EVENTS_MAX];
    int               count = 20; // default

    if (aMsg != nullptr)
    {
        blobmsg_parse(getEventsPolicy, EVENTS_MAX, tb, blob_data(aMsg), blob_len(aMsg));
        if (tb[EVENTS_COUNT] != nullptr)
        {
            count = blobmsg_get_u32(tb[EVENTS_COUNT]);
            if (count <= 0)
                count = 20;
            if (count > (int)kMaxEventLogSize)
                count = (int)kMaxEventLogSize;
        }
    }

    blob_buf_init(&mBuf, 0);

    {
        std::lock_guard<std::mutex> lock(mEventLogMutex);

        blobmsg_add_u32(&mBuf, "TotalEvents", (uint32_t)mEventLog.size());

        void *evtArray = blobmsg_open_array(&mBuf, "Events");

        // Output the most recent `count` entries
        int start = (int)mEventLog.size() - count;
        if (start < 0)
            start = 0;

        for (int i = start; i < (int)mEventLog.size(); i++)
        {
            const EventLogEntry &entry = mEventLog[i];

            void *evtItem = blobmsg_open_table(&mBuf, nullptr);
            blobmsg_add_u64(&mBuf, "Timestamp", (uint64_t)entry.mTimestamp);
            blobmsg_add_string(&mBuf, "Type", entry.mType.c_str());
            blobmsg_add_string(&mBuf, "Detail", entry.mDetail.c_str());

            // Convert timestamp to human-readable
            char timebuf[32];
            struct tm *tm_info = localtime(&entry.mTimestamp);
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
            blobmsg_add_string(&mBuf, "Time", timebuf);

            blobmsg_close_table(&mBuf, evtItem);
        }

        blobmsg_close_array(&mBuf, evtArray);
    }

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: bbrstatus ==============================
// ubus call otbr-agent bbrstatus
// Returns Backbone Router status information:
//   - Border Agent state and port
//   - Local BBR state (disabled/secondary/primary)
//   - Local BBR config (sequence, reregistration delay, MLR timeout)
//   - Primary BBR info (server16, sequence, delay, timeout)
//   - Domain prefix (if available)
//   - Multicast listeners
//   - Border Routing state (if enabled)

int UbusAgentExt::HandleBbr(struct ubus_context *aContext, struct ubus_object *aObj,
                            struct ubus_request_data *aRequest, const char *aMethod,
                            struct blob_attr *aMsg)
{
    (void)aObj;
    (void)aMethod;
    (void)aMsg;
    return GetInstance().BbrDetail(aContext, aRequest);
}

int UbusAgentExt::BbrDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // --- Border Agent info (always available) ---
    {
        void *baTable = blobmsg_open_table(&mBuf, "BorderAgent");

        otBorderAgentState baState = otBorderAgentGetState(instance);
        const char *baStateStr = "unknown";
        switch (baState)
        {
        case OT_BORDER_AGENT_STATE_STOPPED:
            baStateStr = "stopped";
            break;
        case OT_BORDER_AGENT_STATE_STARTED:
            baStateStr = "started";
            break;
        case OT_BORDER_AGENT_STATE_ACTIVE:
            baStateStr = "active";
            break;
        }
        blobmsg_add_string(&mBuf, "State", baStateStr);
        blobmsg_add_u32(&mBuf, "Port", otBorderAgentGetUdpPort(instance));

        blobmsg_close_table(&mBuf, baTable);
    }

#if OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
    // --- Local BBR state (flattened to outer level) ---
    {
        otBackboneRouterState bbrState = otBackboneRouterGetState(instance);
        const char *stateStr = "disabled";
        switch (bbrState)
        {
        case OT_BACKBONE_ROUTER_STATE_DISABLED:
            stateStr = "disabled";
            break;
        case OT_BACKBONE_ROUTER_STATE_SECONDARY:
            stateStr = "secondary";
            break;
        case OT_BACKBONE_ROUTER_STATE_PRIMARY:
            stateStr = "primary";
            break;
        }
        blobmsg_add_string(&mBuf, "State", stateStr);

        // Local BBR config
        otBackboneRouterConfig localConfig;
        otBackboneRouterGetConfig(instance, &localConfig);
        blobmsg_add_u32(&mBuf, "SequenceNumber", localConfig.mSequenceNumber);
        blobmsg_add_u32(&mBuf, "ReregistrationDelay", localConfig.mReregistrationDelay);
        blobmsg_add_u32(&mBuf, "MlrTimeout", localConfig.mMlrTimeout);
    }
#endif // OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE

    // --- Primary BBR info (available on all Thread devices) ---
    {
        void *primaryTable = blobmsg_open_table(&mBuf, "PrimaryBbr");

        otBackboneRouterConfig primaryConfig;
        otError err = otBackboneRouterGetPrimary(instance, &primaryConfig);
        if (err == OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "Exists", "true");
            char rloc16Str[7];
            sprintf(rloc16Str, "0x%04x", primaryConfig.mServer16);
            blobmsg_add_string(&mBuf, "Server16", rloc16Str);
            blobmsg_add_u32(&mBuf, "SequenceNumber", primaryConfig.mSequenceNumber);
            blobmsg_add_u32(&mBuf, "ReregistrationDelay", primaryConfig.mReregistrationDelay);
            blobmsg_add_u32(&mBuf, "MlrTimeout", primaryConfig.mMlrTimeout);
        }
        else
        {
            blobmsg_add_string(&mBuf, "Exists", "false");
        }

        blobmsg_close_table(&mBuf, primaryTable);
    }

#if OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
    // --- Domain Prefix ---
    {
        otBorderRouterConfig domainConfig;
        otError err = otBackboneRouterGetDomainPrefix(instance, &domainConfig);
        if (err == OT_ERROR_NONE)
        {
            void *domainTable = blobmsg_open_table(&mBuf, "DomainPrefix");

            char prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&domainConfig.mPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_add_u8(&mBuf, "Preferred", domainConfig.mPreferred);
            blobmsg_add_u8(&mBuf, "Slaac", domainConfig.mSlaac);
            blobmsg_add_u8(&mBuf, "Dhcp", domainConfig.mDhcp);
            blobmsg_add_u8(&mBuf, "Stable", domainConfig.mStable);
            blobmsg_add_u8(&mBuf, "OnMesh", domainConfig.mOnMesh);

            blobmsg_close_table(&mBuf, domainTable);
        }
    }

    // --- Multicast Listeners ---
    {
        void *mlArray = blobmsg_open_array(&mBuf, "MulticastListeners");

        otBackboneRouterMulticastListenerIterator mlIterator = OT_BACKBONE_ROUTER_MULTICAST_LISTENER_ITERATOR_INIT;
        otBackboneRouterMulticastListenerInfo     mlInfo;

        while (otBackboneRouterMulticastListenerGetNext(instance, &mlIterator, &mlInfo) == OT_ERROR_NONE)
        {
            void *mlItem = blobmsg_open_table(&mBuf, nullptr);

            char addrStr[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6AddressToString(&mlInfo.mAddress, addrStr, sizeof(addrStr));
            blobmsg_add_string(&mBuf, "Address", addrStr);
            blobmsg_add_u32(&mBuf, "Timeout", mlInfo.mTimeout);

            blobmsg_close_table(&mBuf, mlItem);
        }

        blobmsg_close_array(&mBuf, mlArray);
    }
#endif // OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE

#if OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE
    // --- Border Routing state ---
    {
        void *brTable = blobmsg_open_table(&mBuf, "BorderRouting");

        otBorderRoutingState brState = otBorderRoutingGetState(instance);
        const char *brStateStr = "unknown";
        switch (brState)
        {
        case OT_BORDER_ROUTING_STATE_UNINITIALIZED:
            brStateStr = "uninitialized";
            break;
        case OT_BORDER_ROUTING_STATE_DISABLED:
            brStateStr = "disabled";
            break;
        case OT_BORDER_ROUTING_STATE_STOPPED:
            brStateStr = "stopped";
            break;
        case OT_BORDER_ROUTING_STATE_RUNNING:
            brStateStr = "running";
            break;
        }
        blobmsg_add_string(&mBuf, "State", brStateStr);

        // OMR prefix
        otIp6Prefix omrPrefix;
        if (otBorderRoutingGetOmrPrefix(instance, &omrPrefix) == OT_ERROR_NONE)
        {
            char prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&omrPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "OmrPrefix", prefixStr);
        }

        // On-link prefix
        otIp6Prefix onLinkPrefix;
        if (otBorderRoutingGetOnLinkPrefix(instance, &onLinkPrefix) == OT_ERROR_NONE)
        {
            char prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&onLinkPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "OnlinkPrefix", prefixStr);
        }

        blobmsg_close_table(&mBuf, brTable);
    }
#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ===================== UCI Configuration =======================

/**
 * Parse a hex string (e.g. "dead00beef00cafe") into a byte array.
 * Returns number of bytes parsed, or -1 on error.
 */
int UbusAgentExt::HexStringToBytes(const char *aHexStr, uint8_t *aBytes, size_t aMaxLen)
{
    if (aHexStr == nullptr || aBytes == nullptr)
    {
        return -1;
    }

    size_t hexLen = strlen(aHexStr);

    // Skip optional "0x" or "0X" prefix
    if (hexLen >= 2 && aHexStr[0] == '0' && (aHexStr[1] == 'x' || aHexStr[1] == 'X'))
    {
        aHexStr += 2;
        hexLen  -= 2;
    }

    if (hexLen % 2 != 0)
    {
        return -1;
    }

    size_t byteLen = hexLen / 2;

    if (byteLen > aMaxLen)
    {
        return -1;
    }

    for (size_t i = 0; i < byteLen; i++)
    {
        char hi = aHexStr[2 * i];
        char lo = aHexStr[2 * i + 1];
        uint8_t val = 0;

        if (hi >= '0' && hi <= '9')      val = (hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') val = (hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') val = (hi - 'A' + 10) << 4;
        else return -1;

        if (lo >= '0' && lo <= '9')      val |= (lo - '0');
        else if (lo >= 'a' && lo <= 'f') val |= (lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') val |= (lo - 'A' + 10);
        else return -1;

        aBytes[i] = val;
    }

    return static_cast<int>(byteLen);
}

/**
 * Read Thread network config from UCI file /etc/config/otbr.
 * Parses config section 'otbr' for disabled, channel, networkname, passphrase.
 * Also reads srp_server, bbr, nat64 sections for feature flags.
 * UART/GPIO related options are ignored.
 */
bool UbusAgentExt::ReadUciConfig(UciThreadConfig &aConfig)
{
    struct uci_context *uciCtx = nullptr;
    struct uci_package *pkg    = nullptr;
    struct uci_section *secOtbr = nullptr;

    memset(&aConfig, 0, sizeof(aConfig));

    uciCtx = uci_alloc_context();
    if (uciCtx == nullptr)
    {
        otbrLogErr("otbr-agent: Failed to allocate UCI context");
        return false;
    }

    if (uci_load(uciCtx, "otbr", &pkg) != UCI_OK || pkg == nullptr)
    {
        otbrLogWarning("otbr-agent: UCI package 'otbr' not found, skip config");
        uci_free_context(uciCtx);
        return false;
    }

    // Find section "service" named "otbr"
    struct uci_element *elem;
    uci_foreach_element(&pkg->sections, elem)
    {
        struct uci_section *sec = uci_to_section(elem);

        if (strcmp(sec->type, "service") != 0)
        {
            continue;
        }

        const char *name = sec->e.name;
        if (name == nullptr)
        {
            continue;
        }

        // Find otbr service section
        if (strcmp(name, "otbr") == 0)
        {
            secOtbr = sec;
        }
    }

    if (secOtbr == nullptr)
    {
        otbrLogWarning("otbr-agent: UCI section 'service.otbr' not found");
        uci_unload(uciCtx, pkg);
        uci_free_context(uciCtx);
        return false;
    }

    // --- Parse otbr section ---

    // inited (tracks whether random initialization has been done)
    const char *inited = uci_lookup_option_string(uciCtx, secOtbr, "inited");
    if (inited != nullptr && !strcmp(inited, "1"))
    {
        aConfig.mInited = true;
    }
    else
    {
        aConfig.mInited = false;
    }

    const char *logLevel = uci_lookup_option_string(uciCtx, secOtbr, "log_level");
    if (logLevel != nullptr && strlen(logLevel) > 0)
    {
        if (ParseOtbrLogLevel(logLevel, aConfig.mLogLevel))
        {
            aConfig.mHasLogLevel = true;
        }
        else
        {
            otbrLogWarning("otbr-agent: UCI log_level '%s' is invalid, ignored", logLevel);
        }
    }

    // disabled (inverse of autostart)
    const char *disabled = uci_lookup_option_string(uciCtx, secOtbr, "disabled");
    if (disabled != nullptr && (!strcmp(disabled, "0") || !strcmp(disabled, "false")))
    {
        aConfig.mAutoStart = true;
    }
    else
    {
        aConfig.mAutoStart = false;
    }

    // channel
    const char *channel = uci_lookup_option_string(uciCtx, secOtbr, "channel");
    if (channel != nullptr && strlen(channel) > 0)
    {
        long ch = strtol(channel, nullptr, 10);
        if (ch >= 11 && ch <= 26)
        {
            aConfig.mChannel    = static_cast<uint16_t>(ch);
            aConfig.mHasChannel = true;
        }
        else
        {
            otbrLogWarning("otbr-agent: UCI channel '%s' out of range [11..26], ignored", channel);
        }
    }

    // networkname
    const char *networkname = uci_lookup_option_string(uciCtx, secOtbr, "networkname");
    if (networkname != nullptr && strlen(networkname) > 0)
    {
        strncpy(aConfig.mNetworkName, networkname, OT_NETWORK_NAME_MAX_SIZE);
        aConfig.mNetworkName[OT_NETWORK_NAME_MAX_SIZE] = '\0';
        aConfig.mHasNetworkName = true;
    }

    // passphrase - store for PSKc computation later
    const char *passphrase = uci_lookup_option_string(uciCtx, secOtbr, "passphrase");
    if (passphrase != nullptr && strlen(passphrase) > 0)
    {
        strncpy(aConfig.mPassphrase, passphrase, OT_PASSPHRASE_MAX_LENGTH);
        aConfig.mPassphrase[OT_PASSPHRASE_MAX_LENGTH] = '\0';
        aConfig.mHasPassphrase = true;
        otbrLogInfo("otbr-agent: UCI passphrase found (length=%zu)", strlen(passphrase));
    }

    // Note: UART/GPIO options (uart_baudrate, uart_fc, gpio_rst, gpio_dfu, uart_tty) are ignored

    // --- Parse srp_server section ---
    struct uci_section *secSrpServer = nullptr;
    uci_foreach_element(&pkg->sections, elem)
    {
        struct uci_section *sec = uci_to_section(elem);
        if (strcmp(sec->type, "service") == 0 && sec->e.name != nullptr &&
            strcmp(sec->e.name, "srp_server") == 0)
        {
            secSrpServer = sec;
            break;
        }
    }
    if (secSrpServer != nullptr)
    {
        const char *srpDisabled = uci_lookup_option_string(uciCtx, secSrpServer, "disabled");
        if (srpDisabled != nullptr && (!strcmp(srpDisabled, "0") || !strcmp(srpDisabled, "false")))
        {
            otbrLogInfo("otbr-agent: UCI srp_server enabled");
        }
        else
        {
            otbrLogInfo("otbr-agent: UCI srp_server disabled");
        }
    }

    // --- Parse bbr section ---
    struct uci_section *secBbr = nullptr;
    uci_foreach_element(&pkg->sections, elem)
    {
        struct uci_section *sec = uci_to_section(elem);
        if (strcmp(sec->type, "service") == 0 && sec->e.name != nullptr &&
            strcmp(sec->e.name, "bbr") == 0)
        {
            secBbr = sec;
            break;
        }
    }
    if (secBbr != nullptr)
    {
        const char *bbrIfname = uci_lookup_option_string(uciCtx, secBbr, "ifname");
        if (bbrIfname != nullptr)
        {
            otbrLogInfo("otbr-agent: UCI bbr ifname=%s", bbrIfname);
        }
    }

    // --- Parse border agent mDNS section ---
    struct uci_section *secBa = nullptr;
    uci_foreach_element(&pkg->sections, elem)
    {
        struct uci_section *sec = uci_to_section(elem);
        if (strcmp(sec->type, "service") == 0 && sec->e.name != nullptr && strcmp(sec->e.name, "ba") == 0)
        {
            secBa = sec;
            break;
        }
    }
    if (secBa != nullptr)
    {
        const char *instanceName = uci_lookup_option_string(uciCtx, secBa, "instance_name");
        const char *vendorName   = uci_lookup_option_string(uciCtx, secBa, "vendor_name");
        const char *productName  = uci_lookup_option_string(uciCtx, secBa, "product_name");

        if ((instanceName != nullptr && strlen(instanceName) > 0) ||
            (vendorName != nullptr && strlen(vendorName) > 0) ||
            (productName != nullptr && strlen(productName) > 0))
        {
            if (instanceName != nullptr)
            {
                strncpy(aConfig.mMdnsInstanceName, instanceName, sizeof(aConfig.mMdnsInstanceName) - 1);
                aConfig.mMdnsInstanceName[sizeof(aConfig.mMdnsInstanceName) - 1] = '\0';
            }
            if (vendorName != nullptr)
            {
                strncpy(aConfig.mMdnsVendorName, vendorName, sizeof(aConfig.mMdnsVendorName) - 1);
                aConfig.mMdnsVendorName[sizeof(aConfig.mMdnsVendorName) - 1] = '\0';
            }
            if (productName != nullptr)
            {
                strncpy(aConfig.mMdnsProductName, productName, sizeof(aConfig.mMdnsProductName) - 1);
                aConfig.mMdnsProductName[sizeof(aConfig.mMdnsProductName) - 1] = '\0';
            }
            aConfig.mHasMdnsServiceConfig = true;
        }
    }

    // --- Parse nat64 section ---
    struct uci_section *secNat64 = nullptr;
    uci_foreach_element(&pkg->sections, elem)
    {
        struct uci_section *sec = uci_to_section(elem);
        if (strcmp(sec->type, "service") == 0 && sec->e.name != nullptr &&
            strcmp(sec->e.name, "nat64") == 0)
        {
            secNat64 = sec;
            break;
        }
    }
    if (secNat64 != nullptr)
    {
        const char *nat64Disabled = uci_lookup_option_string(uciCtx, secNat64, "disabled");
        if (nat64Disabled != nullptr && (!strcmp(nat64Disabled, "0") || !strcmp(nat64Disabled, "false")))
        {
            otbrLogInfo("otbr-agent: UCI nat64 enabled");
        }
        else
        {
            otbrLogInfo("otbr-agent: UCI nat64 disabled");
        }
    }

    uci_unload(uciCtx, pkg);
    uci_free_context(uciCtx);

    otbrLogInfo("otbr-agent: UCI config read: inited=%d, autostart=%d, name=%s, ch=%d, log_level=%d",
                aConfig.mInited,
                aConfig.mAutoStart,
                aConfig.mHasNetworkName ? aConfig.mNetworkName : "(none)",
                aConfig.mHasChannel ? aConfig.mChannel : 0,
                aConfig.mHasLogLevel ? static_cast<int>(aConfig.mLogLevel) : -1);

    return true;
}

/**
 * Apply UCI config: build otOperationalDataset, set active dataset, optionally start Thread.
 * Must be called with mNcpThreadMutex NOT held.
 */
otError UbusAgentExt::ApplyUciConfig(const UciThreadConfig &aConfig)
{
    otError              error    = OT_ERROR_NONE;
    otInstance          *instance = mController->GetInstance();
    otOperationalDataset dataset;

    memset(&dataset, 0, sizeof(dataset));

    // Check if we have at least one field to set
    bool hasAnyField = aConfig.mHasNetworkName || aConfig.mHasChannel || aConfig.mHasPanId ||
                       aConfig.mHasExtPanId || aConfig.mHasNetworkKey || aConfig.mHasPskc ||
                       aConfig.mHasMeshLocalPrefix || aConfig.mHasPassphrase;

    if (!hasAnyField)
    {
        otbrLogWarning("otbr-agent: UCI config has no thread network fields, nothing to apply");
        return OT_ERROR_INVALID_ARGS;
    }

    mNcpThreadMutex->lock();

    // Check current role — if already attached, we should not blindly overwrite
    otDeviceRole role = otThreadGetDeviceRole(instance);
    if (role != OT_DEVICE_ROLE_DISABLED && role != OT_DEVICE_ROLE_DETACHED)
    {
        otbrLogWarning("otbr-agent: Thread is already running (role=%s), skip UCI apply. "
                       "Stop Thread first or use force reload.",
                       RoleToString(role));
        mNcpThreadMutex->unlock();
        return OT_ERROR_INVALID_STATE;
    }

    // Build the dataset from UCI config
    // First try to get existing active dataset to preserve any existing fields
    otError getErr = otDatasetGetActive(instance, &dataset);
    if (getErr != OT_ERROR_NONE)
    {
        // No active dataset exists — start fresh
        memset(&dataset, 0, sizeof(dataset));

        // Set a default Active Timestamp so the dataset is considered complete
        dataset.mActiveTimestamp.mSeconds       = 1;
        dataset.mActiveTimestamp.mTicks          = 0;
        dataset.mActiveTimestamp.mAuthoritative  = false;
        dataset.mComponents.mIsActiveTimestampPresent = true;
    }

    // Apply UCI fields
    if (aConfig.mHasNetworkName)
    {
        size_t nameLen = strlen(aConfig.mNetworkName);
        memcpy(dataset.mNetworkName.m8, aConfig.mNetworkName, nameLen + 1);
        dataset.mComponents.mIsNetworkNamePresent = true;
    }

    if (aConfig.mHasChannel)
    {
        dataset.mChannel = aConfig.mChannel;
        dataset.mComponents.mIsChannelPresent = true;
    }

    if (aConfig.mHasPanId)
    {
        dataset.mPanId = aConfig.mPanId;
        dataset.mComponents.mIsPanIdPresent = true;
    }

    if (aConfig.mHasExtPanId)
    {
        memcpy(dataset.mExtendedPanId.m8, aConfig.mExtPanId, OT_EXT_PAN_ID_SIZE);
        dataset.mComponents.mIsExtendedPanIdPresent = true;
    }

    if (aConfig.mHasNetworkKey)
    {
        memcpy(dataset.mNetworkKey.m8, aConfig.mNetworkKey, OT_NETWORK_KEY_SIZE);
        dataset.mComponents.mIsNetworkKeyPresent = true;
    }

    if (aConfig.mHasPassphrase)
    {
        // Compute PSKc from passphrase + current extpanid + networkname in dataset
        const uint8_t *extPanId = dataset.mExtendedPanId.m8;
        const char *networkName = reinterpret_cast<const char *>(dataset.mNetworkName.m8);

        otbr::Psk::Pskc pskcComputer;
        const uint8_t  *pskc = pskcComputer.ComputePskc(extPanId, networkName, aConfig.mPassphrase);

        memcpy(dataset.mPskc.m8, pskc, OT_PSKC_MAX_SIZE);
        dataset.mComponents.mIsPskcPresent = true;

        otbrLogInfo("otbr-agent: PSKc computed from passphrase + extpanid + networkname='%s'", networkName);
    }
    else if (aConfig.mHasPskc)
    {
        memcpy(dataset.mPskc.m8, aConfig.mPskc, OT_PSKC_MAX_SIZE);
        dataset.mComponents.mIsPskcPresent = true;
    }

    if (aConfig.mHasMeshLocalPrefix)
    {
        memcpy(dataset.mMeshLocalPrefix.m8, aConfig.mMeshLocalPrefix, 8);
        dataset.mComponents.mIsMeshLocalPrefixPresent = true;
    }

    // Set the Active Dataset
    error = otDatasetSetActive(instance, &dataset);
    if (error != OT_ERROR_NONE)
    {
        otbrLogErr("otbr-agent: Failed to set Active Dataset from UCI: %s", otThreadErrorToString(error));
        mNcpThreadMutex->unlock();
        return error;
    }

    otbrLogInfo("otbr-agent: Active Dataset set from UCI config");

    // If autostart, enable IPv6 and Thread
    if (aConfig.mAutoStart)
    {
        error = otIp6SetEnabled(instance, true);
        if (error != OT_ERROR_NONE)
        {
            otbrLogErr("otbr-agent: Failed to enable IPv6: %s", otThreadErrorToString(error));
            mNcpThreadMutex->unlock();
            return error;
        }

        error = otThreadSetEnabled(instance, true);
        if (error != OT_ERROR_NONE)
        {
            otbrLogErr("otbr-agent: Failed to start Thread: %s", otThreadErrorToString(error));
            mNcpThreadMutex->unlock();
            return error;
        }

        otbrLogInfo("otbr-agent: Thread started from UCI config (autostart=1)");
    }
    else
    {
        otbrLogInfo("otbr-agent: Dataset applied but autostart=0, Thread not started");
    }

    mNcpThreadMutex->unlock();
    mUciApplied = true;

    // Log event
    std::string detail = std::string("{\"action\":\"uci_apply\",\"autostart\":") +
                         (aConfig.mAutoStart ? "true" : "false") +
                         (aConfig.mHasNetworkName ? std::string(",\"networkname\":\"") + aConfig.mNetworkName + "\"" : "") +
                         (aConfig.mHasChannel ? ",\"channel\":" + std::to_string(aConfig.mChannel) : "") +
                         "}";
    AddEventLog("config", detail);

    return OT_ERROR_NONE;
}

/**
 * Write 'otbr.otbr.inited=1' and 'otbr.otbr.eui64=<hex>' to UCI config /etc/config/otbr.
 * This marks that random network initialization has been completed and persists
 * the device EUI64 captured during first-time initialization.
 */
bool UbusAgentExt::WriteUciInitedAndEui64(const char *aEui64)
{
    struct uci_context *uciCtx = nullptr;
    struct uci_package *pkg    = nullptr;
    struct uci_ptr      initedPtr;
    struct uci_ptr      eui64Ptr;
    bool                success = false;

    if (aEui64 == nullptr || strlen(aEui64) == 0)
    {
        otbrLogErr("otbr-agent: Invalid EUI64 for UCI persistence");
        return false;
    }

    uciCtx = uci_alloc_context();
    if (uciCtx == nullptr)
    {
        otbrLogErr("otbr-agent: Failed to allocate UCI context for writing init state");
        return false;
    }

    if (uci_load(uciCtx, "otbr", &pkg) != UCI_OK || pkg == nullptr)
    {
        otbrLogErr("otbr-agent: Failed to load UCI package 'otbr' for writing init state");
        uci_free_context(uciCtx);
        return false;
    }

    // Build the UCI pointers: otbr.otbr.inited=1 and otbr.otbr.eui64=<hex>
    memset(&initedPtr, 0, sizeof(initedPtr));
    initedPtr.package = "otbr";
    initedPtr.section = "otbr";
    initedPtr.option  = "inited";
    initedPtr.value   = "1";
    initedPtr.p       = pkg;

    memset(&eui64Ptr, 0, sizeof(eui64Ptr));
    eui64Ptr.package = "otbr";
    eui64Ptr.section = "otbr";
    eui64Ptr.option  = "eui64";
    eui64Ptr.value   = aEui64;
    eui64Ptr.p       = pkg;

    // Lookup the section first
    struct uci_element *elem;
    uci_foreach_element(&pkg->sections, elem)
    {
        struct uci_section *sec = uci_to_section(elem);
        if (sec->e.name != nullptr && strcmp(sec->e.name, "otbr") == 0)
        {
            initedPtr.s = sec;
            eui64Ptr.s  = sec;
            break;
        }
    }

    if (initedPtr.s == nullptr)
    {
        otbrLogErr("otbr-agent: UCI section 'otbr' not found for writing init state");
        uci_unload(uciCtx, pkg);
        uci_free_context(uciCtx);
        return false;
    }

    if (uci_set(uciCtx, &eui64Ptr) == UCI_OK && uci_set(uciCtx, &initedPtr) == UCI_OK)
    {
        if (uci_save(uciCtx, pkg) == UCI_OK)
        {
            if (uci_commit(uciCtx, &pkg, false) == UCI_OK)
            {
                otbrLogInfo("otbr-agent: UCI 'otbr.otbr.eui64=%s' and 'otbr.otbr.inited=1' written and committed",
                            aEui64);
                success = true;
            }
            else
            {
                otbrLogErr("otbr-agent: Failed to commit UCI init state");
            }
        }
        else
        {
            otbrLogErr("otbr-agent: Failed to save UCI init state");
        }
    }
    else
    {
        otbrLogErr("otbr-agent: Failed to set UCI 'eui64' or 'inited'");
    }

    uci_unload(uciCtx, pkg);
    uci_free_context(uciCtx);
    return success;
}

/**
 * Called from RegisterOtCallbacks() to automatically apply UCI config on startup.
 *
 * Flow:
 *   - If UCI 'inited=1': random init already done on a previous boot.
 *     Just read the existing active dataset and handle autostart.
 *   - If UCI 'inited' not set:
 *     1. Generate a random Thread network dataset (otDatasetCreateNewNetwork)
 *     2. Overlay UCI config fields (channel, networkname, panid, extpanid, networkkey, etc.)
 *     3. Compute PSKc from passphrase + extpanid + networkname if passphrase is present
 *     4. Set the Active Dataset
 *     5. Write 'inited=1' and EUI64 to UCI so next boot skips random generation
 *     6. If autostart=1, enable IPv6 and start Thread
 */
void UbusAgentExt::TryAutoStartFromUci(void)
{
    UciThreadConfig config;

    if (!ReadUciConfig(config))
    {
        otbrLogInfo("otbr-agent: No UCI thread config found, skip auto-start");
        return;
    }

    if (config.mHasLogLevel)
    {
        otLoggingSetLevel(config.mLogLevel);
    }

#if OTBR_ENABLE_BORDER_AGENT
    if (config.mHasMdnsServiceConfig)
    {
        mPendingMdnsInstanceName     = config.mMdnsInstanceName;
        mPendingMdnsVendorName       = config.mMdnsVendorName;
        mPendingMdnsProductName      = config.mMdnsProductName;
        mHasPendingMdnsServiceConfig = true;
        ApplyPendingMdnsServiceConfig();
    }
#endif

    otError              error    = OT_ERROR_NONE;
    otInstance          *instance = mController->GetInstance();
    otOperationalDataset dataset;
    char                 eui64Str[OT_EXT_ADDRESS_SIZE * 2 + 1] = "";

    memset(&dataset, 0, sizeof(dataset));

    mNcpThreadMutex->lock();

    // If OpenThread auto-attached before we processed UCI, honor UCI disabled=1
    // by explicitly stopping Thread here. Otherwise, keep the existing behavior.
    otDeviceRole role = otThreadGetDeviceRole(instance);
    if (role != OT_DEVICE_ROLE_DISABLED && role != OT_DEVICE_ROLE_DETACHED)
    {
        if (!config.mAutoStart)
        {
            otbrLogWarning("otbr-agent: Thread is already running (role=%s) while UCI autostart=0, stopping Thread",
                           RoleToString(role));

            error = otThreadSetEnabled(instance, false);
            if (error == OT_ERROR_NONE)
            {
                error = otIp6SetEnabled(instance, false);
            }

            if (error != OT_ERROR_NONE)
            {
                otbrLogErr("otbr-agent: Failed to stop Thread for UCI autostart=0: %s",
                           otThreadErrorToString(error));
            }
            else
            {
                otbrLogInfo("otbr-agent: Thread stopped to honor UCI autostart=0");
            }

            mNcpThreadMutex->unlock();
            return;
        }

        otbrLogWarning("otbr-agent: Thread is already running (role=%s), skip UCI auto-start",
                       RoleToString(role));
        mNcpThreadMutex->unlock();
        return;
    }

    // ---- Already initialized (inited=1): use existing dataset ----
    if (config.mInited)
    {
        otbrLogInfo("otbr-agent: UCI inited=1, random init already done on previous boot");

        // Try to get existing active dataset
        otError getErr = otDatasetGetActive(instance, &dataset);
        if (getErr == OT_ERROR_NONE)
        {
            otbrLogInfo("otbr-agent: Active dataset present, using existing dataset");
        }
        else
        {
            // Dataset lost (e.g. flash erased) but inited=1 — re-apply UCI via ApplyUciConfig path
            otbrLogWarning("otbr-agent: inited=1 but no active dataset found, re-applying UCI config");
            mNcpThreadMutex->unlock();

            error = ApplyUciConfig(config);
            if (error != OT_ERROR_NONE)
            {
                otbrLogErr("otbr-agent: Re-apply UCI config failed: %s", otThreadErrorToString(error));
            }
            return;
        }

        // Handle autostart with existing dataset
        if (config.mAutoStart)
        {
            error = otIp6SetEnabled(instance, true);
            if (error == OT_ERROR_NONE)
            {
                error = otThreadSetEnabled(instance, true);
            }
            if (error != OT_ERROR_NONE)
            {
                otbrLogErr("otbr-agent: Failed to start Thread with existing dataset: %s",
                           otThreadErrorToString(error));
            }
            else
            {
                otbrLogInfo("otbr-agent: Thread started with existing dataset (autostart=1)");
            }
        }
        else
        {
            otbrLogInfo("otbr-agent: UCI autostart=0, Thread not started");
        }

        mNcpThreadMutex->unlock();
        return;
    }

    // ---- First-time initialization (inited not set) ----
    otbrLogInfo("otbr-agent: UCI inited not set, performing first-time random init + UCI overlay");

    // Step 1: Generate random Thread network parameters
    error = otDatasetCreateNewNetwork(instance, &dataset);
    if (error != OT_ERROR_NONE)
    {
        otbrLogErr("otbr-agent: Failed to create random network dataset: %s", otThreadErrorToString(error));
        mNcpThreadMutex->unlock();
        return;
    }

    otbrLogInfo("otbr-agent: Random network dataset generated successfully");

    // Step 2: Overlay UCI config fields on top of the random dataset
    if (config.mHasNetworkName)
    {
        size_t nameLen = strlen(config.mNetworkName);
        memset(&dataset.mNetworkName, 0, sizeof(dataset.mNetworkName));
        memcpy(dataset.mNetworkName.m8, config.mNetworkName, nameLen);
        dataset.mComponents.mIsNetworkNamePresent = true;
        otbrLogInfo("otbr-agent: UCI override networkname='%s'", config.mNetworkName);
    }

    if (config.mHasChannel)
    {
        dataset.mChannel = config.mChannel;
        dataset.mComponents.mIsChannelPresent = true;
        otbrLogInfo("otbr-agent: UCI override channel=%u", config.mChannel);
    }

    if (config.mHasPanId)
    {
        dataset.mPanId = config.mPanId;
        dataset.mComponents.mIsPanIdPresent = true;
    }

    if (config.mHasExtPanId)
    {
        memcpy(dataset.mExtendedPanId.m8, config.mExtPanId, OT_EXT_PAN_ID_SIZE);
        dataset.mComponents.mIsExtendedPanIdPresent = true;
    }

    if (config.mHasNetworkKey)
    {
        memcpy(dataset.mNetworkKey.m8, config.mNetworkKey, OT_NETWORK_KEY_SIZE);
        dataset.mComponents.mIsNetworkKeyPresent = true;
    }

    if (config.mHasMeshLocalPrefix)
    {
        memcpy(dataset.mMeshLocalPrefix.m8, config.mMeshLocalPrefix, 8);
        dataset.mComponents.mIsMeshLocalPrefixPresent = true;
    }

    // Step 3: Compute PSKc from passphrase + extpanid + networkname
    // PSKc = PBKDF2(passphrase, "Thread" || extpanid || networkname)
    // The extpanid and networkname used are the FINAL values (after UCI override)
    if (config.mHasPassphrase)
    {
        const uint8_t *extPanId = dataset.mExtendedPanId.m8;
        const char *networkName = reinterpret_cast<const char *>(dataset.mNetworkName.m8);

        otbr::Psk::Pskc pskcComputer;
        const uint8_t  *pskc = pskcComputer.ComputePskc(extPanId, networkName, config.mPassphrase);

        memcpy(dataset.mPskc.m8, pskc, OT_PSKC_MAX_SIZE);
        dataset.mComponents.mIsPskcPresent = true;

        otbrLogInfo("otbr-agent: PSKc computed from passphrase + extpanid + networkname='%s'", networkName);
    }
    else if (config.mHasPskc)
    {
        memcpy(dataset.mPskc.m8, config.mPskc, OT_PSKC_MAX_SIZE);
        dataset.mComponents.mIsPskcPresent = true;
    }

    // Step 4: Set the Active Dataset
    error = otDatasetSetActive(instance, &dataset);
    if (error != OT_ERROR_NONE)
    {
        otbrLogErr("otbr-agent: Failed to set Active Dataset: %s", otThreadErrorToString(error));
        mNcpThreadMutex->unlock();
        return;
    }

    otbrLogInfo("otbr-agent: Active Dataset set (random base + UCI override)");

    otExtAddress eui64;
    otLinkGetFactoryAssignedIeeeEui64(instance, &eui64);
    OutputBytes(eui64.m8, OT_EXT_ADDRESS_SIZE, eui64Str);

    // Step 5: Write 'inited=1' and EUI64 to UCI to prevent re-randomization on next reboot
    mNcpThreadMutex->unlock();
    if (!WriteUciInitedAndEui64(eui64Str))
    {
        otbrLogWarning("otbr-agent: Failed to persist EUI64 '%s' and inited flag to UCI", eui64Str);
    }
    mNcpThreadMutex->lock();

    // Step 6: If autostart, enable IPv6 and Thread
    if (config.mAutoStart)
    {
        error = otIp6SetEnabled(instance, true);
        if (error != OT_ERROR_NONE)
        {
            otbrLogErr("otbr-agent: Failed to enable IPv6: %s", otThreadErrorToString(error));
            mNcpThreadMutex->unlock();
            return;
        }

        error = otThreadSetEnabled(instance, true);
        if (error != OT_ERROR_NONE)
        {
            otbrLogErr("otbr-agent: Failed to start Thread: %s", otThreadErrorToString(error));
            mNcpThreadMutex->unlock();
            return;
        }

        otbrLogInfo("otbr-agent: Thread started from UCI config (autostart=1)");
    }
    else
    {
        otbrLogInfo("otbr-agent: Dataset applied but autostart=0, Thread not started");
    }

    mNcpThreadMutex->unlock();
    mUciApplied = true;

    // Log event
    std::string detail = std::string("{\"action\":\"uci_first_init\",\"autostart\":") +
                         (config.mAutoStart ? "true" : "false") +
                         (config.mHasNetworkName ? std::string(",\"networkname\":\"") + config.mNetworkName + "\"" : "") +
                         (config.mHasChannel ? ",\"channel\":" + std::to_string(config.mChannel) : "") +
                         ",\"pskc_from_passphrase\":" + (config.mHasPassphrase ? "true" : "false") +
                         "}";
    AddEventLog("config", detail);
}

// ===================== ubus handlers for UCI =====================

int UbusAgentExt::HandleUciConfig(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
                                  struct ubus_request_data *aRequest,
                                  const char               *aMethod,
                                  struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return sAgentInstance->UciConfigDetail(aContext, aRequest);
}

int UbusAgentExt::HandleUciApply(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return sAgentInstance->UciApplyDetail(aContext, aRequest);
}

/**
 * ubus call otbr-agent uciconfig
 * Returns the current UCI thread network configuration (read-only, does not apply).
 */
int UbusAgentExt::UciConfigDetail(struct ubus_context      *aContext,
                                  struct ubus_request_data *aRequest)
{
    UciThreadConfig config;

    blob_buf_init(&mBuf, 0);

    if (!ReadUciConfig(config))
    {
        blobmsg_add_string(&mBuf, "Error", "UCI package 'otbr' not found or no 'thread' section");
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return UBUS_STATUS_NOT_FOUND;
    }

    blobmsg_add_u8(&mBuf, "Autostart", config.mAutoStart ? 1 : 0);
    blobmsg_add_u8(&mBuf, "Applied", mUciApplied ? 1 : 0);

    if (config.mHasNetworkName)
    {
        blobmsg_add_string(&mBuf, "NetworkName", config.mNetworkName);
    }

    if (config.mHasChannel)
    {
        blobmsg_add_u32(&mBuf, "Channel", config.mChannel);
    }

    if (config.mHasPanId)
    {
        char panidStr[8];
        snprintf(panidStr, sizeof(panidStr), "0x%04x", config.mPanId);
        blobmsg_add_string(&mBuf, "PanId", panidStr);
    }

    if (config.mHasExtPanId)
    {
        char hexStr[OT_EXT_PAN_ID_SIZE * 2 + 1];
        OutputBytes(config.mExtPanId, OT_EXT_PAN_ID_SIZE, hexStr);
        blobmsg_add_string(&mBuf, "ExtPanId", hexStr);
    }

    if (config.mHasNetworkKey)
    {
        char hexStr[OT_NETWORK_KEY_SIZE * 2 + 1];
        OutputBytes(config.mNetworkKey, OT_NETWORK_KEY_SIZE, hexStr);
        blobmsg_add_string(&mBuf, "NetworkKey", hexStr);
    }

    if (config.mHasPskc)
    {
        char hexStr[OT_PSKC_MAX_SIZE * 2 + 1];
        OutputBytes(config.mPskc, OT_PSKC_MAX_SIZE, hexStr);
        blobmsg_add_string(&mBuf, "Pskc", hexStr);
    }

    if (config.mHasMeshLocalPrefix)
    {
        char prefixStr[INET6_ADDRSTRLEN];
        struct in6_addr addr6;
        memset(&addr6, 0, sizeof(addr6));
        memcpy(addr6.s6_addr, config.mMeshLocalPrefix, 8);
        inet_ntop(AF_INET6, &addr6, prefixStr, sizeof(prefixStr));
        // Append /64
        char fullPrefix[INET6_ADDRSTRLEN + 4];
        snprintf(fullPrefix, sizeof(fullPrefix), "%s/64", prefixStr);
        blobmsg_add_string(&mBuf, "MeshLocalPrefix", fullPrefix);
    }

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

/**
 * ubus call otbr-agent uciapply
 * Re-read UCI config and apply it (set dataset, optionally start Thread).
 * If Thread is already running, returns error unless stopped first.
 */
int UbusAgentExt::UciApplyDetail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest)
{
    UciThreadConfig config;

    blob_buf_init(&mBuf, 0);

    if (!ReadUciConfig(config))
    {
        blobmsg_add_string(&mBuf, "Error", "UCI package 'otbr' not found or no 'thread' section");
        blobmsg_add_string(&mBuf, "Result", "failed");
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return UBUS_STATUS_NOT_FOUND;
    }

    otError error = ApplyUciConfig(config);

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Result", "success");
        blobmsg_add_u8(&mBuf, "Autostart", config.mAutoStart ? 1 : 0);
        if (config.mHasNetworkName)
        {
            blobmsg_add_string(&mBuf, "NetworkName", config.mNetworkName);
        }
        if (config.mHasChannel)
        {
            blobmsg_add_u32(&mBuf, "Channel", config.mChannel);
        }
        if (config.mHasPanId)
        {
            char panidStr[8];
            snprintf(panidStr, sizeof(panidStr), "0x%04x", config.mPanId);
            blobmsg_add_string(&mBuf, "PanId", panidStr);
        }
    }
    else if (error == OT_ERROR_INVALID_STATE)
    {
        blobmsg_add_string(&mBuf, "Result", "failed");
        blobmsg_add_string(&mBuf, "Error", "Thread is already running. Stop Thread first (ubus call otbr threadstop) then retry.");
    }
    else if (error == OT_ERROR_INVALID_ARGS)
    {
        blobmsg_add_string(&mBuf, "Result", "failed");
        blobmsg_add_string(&mBuf, "Error", "No valid thread network fields in UCI config");
    }
    else
    {
        blobmsg_add_string(&mBuf, "Result", "failed");
        char errMsg[64];
        snprintf(errMsg, sizeof(errMsg), "OpenThread error: %s", otThreadErrorToString(error));
        blobmsg_add_string(&mBuf, "Error", errMsg);
    }

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ===================== mDNS Service Configuration ==============

#if OTBR_ENABLE_BORDER_AGENT
void UbusAgentExt::SetBorderAgent(BorderAgent *aBorderAgent)
{
    mBorderAgent = aBorderAgent;
    otbrLogInfo("otbr-agent: BorderAgent reference set for mDNS config");
    ApplyPendingMdnsServiceConfig();
}

void UbusAgentExt::ApplyPendingMdnsServiceConfig(void)
{
    if (!mHasPendingMdnsServiceConfig || mBorderAgent == nullptr)
    {
        return;
    }

    otbrError err = mBorderAgent->SetMeshCopServiceValues(mPendingMdnsInstanceName,
                                                          mPendingMdnsProductName,
                                                          mPendingMdnsVendorName,
                                                          std::vector<uint8_t>{});

    if (err == OTBR_ERROR_NONE)
    {
        otbrLogInfo("otbr-agent: Applied UCI mDNS service config: vendor=%s product=%s instance=%s",
                    mPendingMdnsVendorName.c_str(),
                    mPendingMdnsProductName.c_str(),
                    mPendingMdnsInstanceName.c_str());
        mHasPendingMdnsServiceConfig = false;
    }
    else
    {
        otbrLogWarning("otbr-agent: Failed to apply UCI mDNS service config: %d", err);
    }
}
#endif

// ================ Handler: setmdns =============================
// ubus call otbr-agent setmdns '{"vendor_name":"MyVendor","product_name":"MyProduct","instance_name":"MyBR"}'
// Optional: vendor_oui (hex string, 6 chars = 3 bytes, e.g. "AABBCC")
// Sets mDNS MeshCoP service values (vendor name, product name, base instance name)

int UbusAgentExt::HandleSetMdns(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
                                struct ubus_request_data *aRequest,
                                const char               *aMethod,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SetMdnsDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetMdnsDetail(struct ubus_context      *aContext,
                                struct ubus_request_data *aRequest,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aMsg);
    blob_buf_init(&mBuf, 0);

#if OTBR_ENABLE_BORDER_AGENT
    if (mBorderAgent == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "border_agent_not_available");
        blobmsg_add_u32(&mBuf, "ErrorCode", 1);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    struct blob_attr *tb[MDNS_MAX];
    std::string       vendorName;
    std::string       productName;
    std::string       instanceName;
    std::vector<uint8_t> vendorOui;

    if (aMsg != nullptr)
    {
        blobmsg_parse(setMdnsPolicy, MDNS_MAX, tb, blob_data(aMsg), blob_len(aMsg));

        if (tb[MDNS_VENDOR_NAME] != nullptr)
            vendorName = blobmsg_get_string(tb[MDNS_VENDOR_NAME]);

        if (tb[MDNS_PRODUCT_NAME] != nullptr)
            productName = blobmsg_get_string(tb[MDNS_PRODUCT_NAME]);

        if (tb[MDNS_INSTANCE_NAME] != nullptr)
            instanceName = blobmsg_get_string(tb[MDNS_INSTANCE_NAME]);

        if (tb[MDNS_VENDOR_OUI] != nullptr)
        {
            const char *ouiHex = blobmsg_get_string(tb[MDNS_VENDOR_OUI]);
            size_t ouiLen = strlen(ouiHex);
            if (ouiLen == 6) // 3 bytes = 6 hex chars
            {
                uint8_t ouiBytes[3];
                if (HexStringToBytes(ouiHex, ouiBytes, 3) == 3)
                {
                    vendorOui.assign(ouiBytes, ouiBytes + 3);
                }
            }
        }
    }

    if (vendorName.empty() && productName.empty() && instanceName.empty())
    {
        blobmsg_add_string(&mBuf, "Error", "at_least_one_field_required");
        blobmsg_add_u32(&mBuf, "ErrorCode", 1);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    // Use instance name or build from vendor+product if not specified
    if (instanceName.empty())
    {
        if (!vendorName.empty() && !productName.empty())
            instanceName = vendorName + " " + productName;
        else if (!vendorName.empty())
            instanceName = vendorName;
        else
            instanceName = productName;
    }

    otbrError err = mBorderAgent->SetMeshCopServiceValues(instanceName, productName, vendorName, vendorOui);

    if (err == OTBR_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Status", "success");
        if (!vendorName.empty())
            blobmsg_add_string(&mBuf, "VendorName", vendorName.c_str());
        if (!productName.empty())
            blobmsg_add_string(&mBuf, "ProductName", productName.c_str());
        blobmsg_add_string(&mBuf, "InstanceName", instanceName.c_str());

        otbrLogInfo("otbr-agent: mDNS service values set: vendor=%s product=%s instance=%s",
                    vendorName.c_str(), productName.c_str(), instanceName.c_str());
        AddEventLog("mdns", std::string("setmdns vendor=") + vendorName +
                    " product=" + productName + " instance=" + instanceName);
    }
    else
    {
        blobmsg_add_string(&mBuf, "Status", "failed");
        blobmsg_add_string(&mBuf, "Error", "invalid_args_or_already_enabled");
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", err);
#else
    blobmsg_add_string(&mBuf, "Error", "border_agent_not_compiled");
    blobmsg_add_u32(&mBuf, "ErrorCode", 1);
#endif // OTBR_ENABLE_BORDER_AGENT && MDNS

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Commissioner callbacks ======================

static const char *CommissionerStateToString(otCommissionerState aState)
{
    switch (aState)
    {
    case OT_COMMISSIONER_STATE_DISABLED:
        return "disabled";
    case OT_COMMISSIONER_STATE_PETITION:
        return "petition";
    case OT_COMMISSIONER_STATE_ACTIVE:
        return "active";
    default:
        return "unknown";
    }
}

static const char *CommissionerJoinerEventToString(otCommissionerJoinerEvent aEvent)
{
    switch (aEvent)
    {
    case OT_COMMISSIONER_JOINER_START:
        return "start";
    case OT_COMMISSIONER_JOINER_CONNECTED:
        return "connected";
    case OT_COMMISSIONER_JOINER_FINALIZE:
        return "finalize";
    case OT_COMMISSIONER_JOINER_END:
        return "end";
    case OT_COMMISSIONER_JOINER_REMOVED:
        return "removed";
    default:
        return "unknown";
    }
}

void CommissionerStateCallback(otCommissionerState aState, void *aContext)
{
    OT_UNUSED_VARIABLE(aContext);

    if (sAgentInstance != nullptr)
    {
        sAgentInstance->HandleCommissionerStateChanged(aState);
    }
}

void UbusAgentExt::HandleCommissionerStateChanged(otCommissionerState aState)
{
    const char *stateStr = CommissionerStateToString(aState);

    otbrLogInfo("otbr-agent: commissioner state changed: %s", stateStr);
    AddEventLog("commissioner", std::string("state_changed:") + stateStr);

    blob_buf_init(&mEventBuf, 0);
    blobmsg_add_string(&mEventBuf, "event", "commissioner_state_changed");
    blobmsg_add_string(&mEventBuf, "state", stateStr);
    blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
    SendUbusEvent("otbr-agent.commissioner", mEventBuf.head);

    if (aState == OT_COMMISSIONER_STATE_DISABLED)
    {
        CancelCommissionerTimeout();
    }
}

void UbusAgentExt::HandleCommissionerTimeoutTimer(struct uloop_timeout *aTimeout)
{
    OT_UNUSED_VARIABLE(aTimeout);
    UbusAgentExt &instance = GetInstance();

    otbrLogInfo("otbr-agent: commissioner timeout reached, auto-stopping");
    instance.AddEventLog("commissioner", "timeout_auto_stop");

    blob_buf_init(&instance.mEventBuf, 0);
    blobmsg_add_string(&instance.mEventBuf, "event", "commissioner_timeout_expired");
    blobmsg_add_u64(&instance.mEventBuf, "Timestamp", (uint64_t)time(nullptr));
    instance.SendUbusEvent("otbr-agent.commissioner", instance.mEventBuf.head);

    instance.mNcpThreadMutex->lock();
    otInstance *otInstance = instance.mController->GetInstance();
    otCommissionerStop(otInstance);
    instance.mNcpThreadMutex->unlock();
}

void UbusAgentExt::CancelCommissionerTimeout(void)
{
    uloop_timeout_cancel(&mCommissionerTimeoutTimer);
    memset(&mCommissionerTimeoutTimer, 0, sizeof(mCommissionerTimeoutTimer));
}

void CommissionerJoinerEventCallback(otCommissionerJoinerEvent aEvent,
                                     const otJoinerInfo       *aJoinerInfo,
                                     const otExtAddress       *aJoinerId,
                                     void                     *aContext)
{
    OT_UNUSED_VARIABLE(aContext);

    if (sAgentInstance != nullptr)
    {
        sAgentInstance->HandleCommissionerJoinerEvent(aEvent, aJoinerInfo, aJoinerId);
    }
}

void UbusAgentExt::HandleCommissionerJoinerEvent(otCommissionerJoinerEvent aEvent,
                                                  const otJoinerInfo       *aJoinerInfo,
                                                  const otExtAddress       *aJoinerId)
{
    const char *eventStr = CommissionerJoinerEventToString(aEvent);

    otbrLogInfo("otbr-agent: commissioner joiner event: %s", eventStr);
    AddEventLog("commissioner", std::string("joiner_event:") + eventStr);

    blob_buf_init(&mEventBuf, 0);
    blobmsg_add_string(&mEventBuf, "event", "commissioner_joiner_event");
    blobmsg_add_string(&mEventBuf, "joiner_event", eventStr);

    if (aJoinerId != nullptr)
    {
        char eui64Str[OT_EXT_ADDRESS_SIZE * 2 + 1];
        OutputBytes(aJoinerId->m8, OT_EXT_ADDRESS_SIZE, eui64Str);
        blobmsg_add_string(&mEventBuf, "joiner_id", eui64Str);
    }

    if (aJoinerInfo != nullptr)
    {
        switch (aJoinerInfo->mType)
        {
        case OT_JOINER_INFO_TYPE_ANY:
            blobmsg_add_string(&mEventBuf, "joiner_type", "any");
            break;
        case OT_JOINER_INFO_TYPE_EUI64:
        {
            char eui64Str[OT_EXT_ADDRESS_SIZE * 2 + 1];
            OutputBytes(aJoinerInfo->mSharedId.mEui64.m8, OT_EXT_ADDRESS_SIZE, eui64Str);
            blobmsg_add_string(&mEventBuf, "joiner_type", "eui64");
            blobmsg_add_string(&mEventBuf, "joiner_eui64", eui64Str);
            break;
        }
        case OT_JOINER_INFO_TYPE_DISCERNER:
            blobmsg_add_string(&mEventBuf, "joiner_type", "discerner");
            break;
        }
    }

    blobmsg_add_u64(&mEventBuf, "timestamp", (uint64_t)time(nullptr));
    SendUbusEvent("otbr-agent.commissioner", mEventBuf.head);
}

// ================ Handler: commissionerstart ==================
// ubus call otbr-agent commissionerstart
// Starts the Commissioner role

int UbusAgentExt::HandleCommissionerStart(struct ubus_context      *aContext,
                                          struct ubus_object       *aObj,
                                          struct ubus_request_data *aRequest,
                                          const char               *aMethod,
                                          struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().CommissionerStartDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::CommissionerStartDetail(struct ubus_context      *aContext,
                                          struct ubus_request_data *aRequest,
                                          struct blob_attr         *aMsg)
{
    blob_buf_init(&mBuf, 0);

    uint32_t timeoutSec = 0;
    if (aMsg != nullptr)
    {
        struct blob_attr *tb[COMMISSIONER_START_MAX];
        blobmsg_parse(commissionerStartPolicy, COMMISSIONER_START_MAX, tb, blob_data(aMsg), blob_len(aMsg));
        if (tb[COMMISSIONER_START_TIMEOUT] != nullptr)
        {
            timeoutSec = blobmsg_get_u32(tb[COMMISSIONER_START_TIMEOUT]);
        }
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otCommissionerState currentState = otCommissionerGetState(instance);

    otError error = OT_ERROR_NONE;
    bool    alreadyActive = false;

    if (currentState == OT_COMMISSIONER_STATE_DISABLED)
    {
        error = otCommissionerStart(instance,
                                    &CommissionerStateCallback,
                                    &CommissionerJoinerEventCallback,
                                    nullptr);
    }
    else if (currentState == OT_COMMISSIONER_STATE_ACTIVE)
    {
        alreadyActive = true;
    }
    else
    {
        error = OT_ERROR_ALREADY;
    }

    const char *stateStr = CommissionerStateToString(otCommissionerGetState(instance));

    if (error == OT_ERROR_NONE)
    {
        if (alreadyActive)
        {
            blobmsg_add_string(&mBuf, "Status", "already_active");
            otbrLogInfo("otbr-agent: commissioner already active");
        }
        else
        {
            blobmsg_add_string(&mBuf, "Status", "started");
            otbrLogInfo("otbr-agent: commissioner started, timeout=%u s", timeoutSec);
            AddEventLog("commissioner", "commissioner_started");

            blob_buf_init(&mEventBuf, 0);
            blobmsg_add_string(&mEventBuf, "event", "commissioner_started");
            blobmsg_add_string(&mEventBuf, "State", stateStr);
            blobmsg_add_u64(&mEventBuf, "Timestamp", (uint64_t)time(nullptr));
            SendUbusEvent("otbr-agent.commissioner", mEventBuf.head);
        }

        if (timeoutSec > 0)
        {
            memset(&mCommissionerTimeoutTimer, 0, sizeof(mCommissionerTimeoutTimer));
            mCommissionerTimeoutTimer.cb = &UbusAgentExt::HandleCommissionerTimeoutTimer;
            uloop_timeout_set(&mCommissionerTimeoutTimer, timeoutSec * 1000);
        }
    }
    else
    {
        blobmsg_add_string(&mBuf, "Status", "failed");
        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));
    }

    blobmsg_add_u32(&mBuf, "ErrorCode", error);
    blobmsg_add_string(&mBuf, "CommissionerState", stateStr);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: commissionerstop ===================
// ubus call otbr-agent commissionerstop
// Stops the Commissioner role

int UbusAgentExt::HandleCommissionerStop(struct ubus_context      *aContext,
                                         struct ubus_object       *aObj,
                                         struct ubus_request_data *aRequest,
                                         const char               *aMethod,
                                         struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().CommissionerStopDetail(aContext, aRequest);
}

int UbusAgentExt::CommissionerStopDetail(struct ubus_context      *aContext,
                                         struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    CancelCommissionerTimeout();

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otError error = otCommissionerStop(instance);

    const char *stateStr = CommissionerStateToString(otCommissionerGetState(instance));

    blobmsg_add_string(&mBuf, "Status", "stopped");
    blobmsg_add_u32(&mBuf, "ErrorCode", error);
    blobmsg_add_string(&mBuf, "CommissionerState", stateStr);

    otbrLogInfo("otbr-agent: commissioner stopped");
    AddEventLog("commissioner", "commissioner_stopped");

    blob_buf_init(&mEventBuf, 0);
    blobmsg_add_string(&mEventBuf, "event", "commissioner_stopped");
    blobmsg_add_string(&mEventBuf, "State", stateStr);
    blobmsg_add_u64(&mEventBuf, "Timestamp", (uint64_t)time(nullptr));
    SendUbusEvent("otbr-agent.commissioner", mEventBuf.head);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: setbbrconfig =============================
// ubus call otbr-agent setbbrconfig '{"enabled":true,"sequence_number":1,"reregistration_delay":300,"mlr_timeout":3600,"register":true,"jitter":51}'
// Sets Backbone Router configuration. All parameters are optional.
//   enabled              - enable/disable BBR functionality
//   sequence_number      - BBR sequence number (0-255)
//   reregistration_delay - reregistration delay in seconds
//   mlr_timeout          - multicast listener registration timeout in seconds
//   register             - trigger explicit BBR registration
//   jitter               - registration jitter value (1-255)

int UbusAgentExt::HandleSetBbr(struct ubus_context      *aContext,
                               struct ubus_object       *aObj,
                               struct ubus_request_data *aRequest,
                               const char               *aMethod,
                               struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SetBbrDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetBbrDetail(struct ubus_context      *aContext,
                               struct ubus_request_data *aRequest,
                               struct blob_attr         *aMsg)
{
    blob_buf_init(&mBuf, 0);

#if OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE
    struct blob_attr *tb[SET_BBR_MAX];

    if (aMsg != nullptr)
    {
        blobmsg_parse(setBbrPolicy, SET_BBR_MAX, tb, blob_data(aMsg), blob_len(aMsg));
    }
    else
    {
        memset(tb, 0, sizeof(tb));
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    bool        configChanged = false;

    // --- Enable/Disable BBR ---
    if (tb[SET_BBR_ENABLED] != nullptr)
    {
        bool enable = blobmsg_get_bool(tb[SET_BBR_ENABLED]);
        otBackboneRouterSetEnabled(instance, enable);
        blobmsg_add_u8(&mBuf, "Enabled", enable);
    }

    // --- Update BBR config (sequence, delay, mlr_timeout) ---
    {
        otBackboneRouterConfig config;
        otBackboneRouterGetConfig(instance, &config);

        if (tb[SET_BBR_SEQUENCE_NUMBER] != nullptr)
        {
            config.mSequenceNumber = (uint8_t)blobmsg_get_u32(tb[SET_BBR_SEQUENCE_NUMBER]);
            configChanged = true;
        }

        if (tb[SET_BBR_REREGISTRATION_DELAY] != nullptr)
        {
            config.mReregistrationDelay = (uint16_t)blobmsg_get_u32(tb[SET_BBR_REREGISTRATION_DELAY]);
            configChanged = true;
        }

        if (tb[SET_BBR_MLR_TIMEOUT] != nullptr)
        {
            config.mMlrTimeout = blobmsg_get_u32(tb[SET_BBR_MLR_TIMEOUT]);
            configChanged = true;
        }

        if (configChanged)
        {
            otBackboneRouterSetConfig(instance, &config);
        }
    }

    // --- Set registration jitter ---
    if (tb[SET_BBR_JITTER] != nullptr)
    {
        uint8_t jitter = (uint8_t)blobmsg_get_u32(tb[SET_BBR_JITTER]);
        otBackboneRouterSetRegistrationJitter(instance, jitter);
        blobmsg_add_u32(&mBuf, "Jitter", jitter);
    }

    // --- Trigger explicit registration ---
    if (tb[SET_BBR_REGISTER] != nullptr && blobmsg_get_bool(tb[SET_BBR_REGISTER]))
    {
        otError regErr = otBackboneRouterRegister(instance);
        blobmsg_add_u32(&mBuf, "RegisterError", regErr);
    }

    // --- Return current state after changes ---
    otBackboneRouterState bbrState = otBackboneRouterGetState(instance);
    const char *stateStr = "disabled";
    switch (bbrState)
    {
    case OT_BACKBONE_ROUTER_STATE_DISABLED:
        stateStr = "disabled";
        break;
    case OT_BACKBONE_ROUTER_STATE_SECONDARY:
        stateStr = "secondary";
        break;
    case OT_BACKBONE_ROUTER_STATE_PRIMARY:
        stateStr = "primary";
        break;
    }
    blobmsg_add_string(&mBuf, "State", stateStr);

    otBackboneRouterConfig currentConfig;
    otBackboneRouterGetConfig(instance, &currentConfig);
    blobmsg_add_u32(&mBuf, "SequenceNumber", currentConfig.mSequenceNumber);
    blobmsg_add_u32(&mBuf, "ReregistrationDelay", currentConfig.mReregistrationDelay);
    blobmsg_add_u32(&mBuf, "MlrTimeout", currentConfig.mMlrTimeout);
    blobmsg_add_u32(&mBuf, "RegistrationJitter", otBackboneRouterGetRegistrationJitter(instance));

    blobmsg_add_string(&mBuf, "Status", "success");

    otbrLogInfo("otbr-agent: BBR config updated");
    AddEventLog("bbr", "setbbrconfig config updated");

    mNcpThreadMutex->unlock();
#else
    blobmsg_add_string(&mBuf, "Status", "unsupported");
    blobmsg_add_string(&mBuf, "Error", "backbone_router_not_enabled");
#endif // OPENTHREAD_CONFIG_BACKBONE_ROUTER_ENABLE

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: setsrpserver =======================
// ubus call otbr-agent setsrpserver '{"enabled":true,"auto_enable":true,"address_mode":"anycast","anycast_seq":1,"domain":"default.service.arpa.","min_lease":1800,"max_lease":7200,"min_key_lease":86400,"max_key_lease":1209600,"min_ttl":60,"max_ttl":3600}'
// Sets SRP Server configuration. All parameters are optional.
//   enabled       - enable/disable SRP server
//   auto_enable   - enable/disable auto-enable mode (Border Routing controls SRP server)
//   address_mode  - "unicast" or "anycast"
//   anycast_seq   - anycast sequence number (0-255, used with anycast mode)
//   domain        - SRP server domain (can only be set when server is disabled)
//   min_lease     - minimum lease interval in seconds
//   max_lease     - maximum lease interval in seconds
//   min_key_lease - minimum key-lease interval in seconds
//   max_key_lease - maximum key-lease interval in seconds
//   min_ttl       - minimum TTL in seconds
//   max_ttl       - maximum TTL in seconds

int UbusAgentExt::HandleSetSrpServer(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
                                     struct ubus_request_data *aRequest,
                                     const char               *aMethod,
                                     struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SetSrpServerDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetSrpServerDetail(struct ubus_context      *aContext,
                                     struct ubus_request_data *aRequest,
                                     struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aMsg);
    blob_buf_init(&mBuf, 0);

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
    struct blob_attr *tb[SET_SRP_MAX];

    if (aMsg != nullptr)
    {
        blobmsg_parse(setSrpServerPolicy, SET_SRP_MAX, tb, blob_data(aMsg), blob_len(aMsg));
    }
    else
    {
        memset(tb, 0, sizeof(tb));
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otError     error    = OT_ERROR_NONE;

    // --- Set domain (must be done before enabling) ---
    if (tb[SET_SRP_DOMAIN] != nullptr)
    {
        const char *domain = blobmsg_get_string(tb[SET_SRP_DOMAIN]);
        error = otSrpServerSetDomain(instance, domain);
        if (error != OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "DomainError", otThreadErrorToString(error));
        }
    }

    // --- Set address mode (must be done before enabling) ---
    if (tb[SET_SRP_ADDRESS_MODE] != nullptr)
    {
        const char *modeStr = blobmsg_get_string(tb[SET_SRP_ADDRESS_MODE]);
        if (strcmp(modeStr, "unicast") == 0)
        {
            error = otSrpServerSetAddressMode(instance, OT_SRP_SERVER_ADDRESS_MODE_UNICAST);
        }
        else if (strcmp(modeStr, "anycast") == 0)
        {
            error = otSrpServerSetAddressMode(instance, OT_SRP_SERVER_ADDRESS_MODE_ANYCAST);
        }
        else
        {
            blobmsg_add_string(&mBuf, "AddressModeError", "invalid_value_use_unicast_or_anycast");
        }
        if (error != OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "AddressModeError", otThreadErrorToString(error));
        }
    }

    // --- Set anycast sequence number ---
    if (tb[SET_SRP_ANYCAST_SEQ] != nullptr)
    {
        uint8_t seq = (uint8_t)blobmsg_get_u32(tb[SET_SRP_ANYCAST_SEQ]);
        error = otSrpServerSetAnycastModeSequenceNumber(instance, seq);
        if (error != OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "AnycastSeqError", otThreadErrorToString(error));
        }
    }

    // --- Set TTL config ---
    if (tb[SET_SRP_MIN_TTL] != nullptr || tb[SET_SRP_MAX_TTL] != nullptr)
    {
        otSrpServerTtlConfig ttlConfig;
        otSrpServerGetTtlConfig(instance, &ttlConfig);

        if (tb[SET_SRP_MIN_TTL] != nullptr)
        {
            ttlConfig.mMinTtl = blobmsg_get_u32(tb[SET_SRP_MIN_TTL]);
        }
        if (tb[SET_SRP_MAX_TTL] != nullptr)
        {
            ttlConfig.mMaxTtl = blobmsg_get_u32(tb[SET_SRP_MAX_TTL]);
        }

        error = otSrpServerSetTtlConfig(instance, &ttlConfig);
        if (error != OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "TtlConfigError", otThreadErrorToString(error));
        }
    }

    // --- Set lease config ---
    if (tb[SET_SRP_MIN_LEASE] != nullptr || tb[SET_SRP_MAX_LEASE] != nullptr ||
        tb[SET_SRP_MIN_KEY_LEASE] != nullptr || tb[SET_SRP_MAX_KEY_LEASE] != nullptr)
    {
        otSrpServerLeaseConfig leaseConfig;
        otSrpServerGetLeaseConfig(instance, &leaseConfig);

        if (tb[SET_SRP_MIN_LEASE] != nullptr)
        {
            leaseConfig.mMinLease = blobmsg_get_u32(tb[SET_SRP_MIN_LEASE]);
        }
        if (tb[SET_SRP_MAX_LEASE] != nullptr)
        {
            leaseConfig.mMaxLease = blobmsg_get_u32(tb[SET_SRP_MAX_LEASE]);
        }
        if (tb[SET_SRP_MIN_KEY_LEASE] != nullptr)
        {
            leaseConfig.mMinKeyLease = blobmsg_get_u32(tb[SET_SRP_MIN_KEY_LEASE]);
        }
        if (tb[SET_SRP_MAX_KEY_LEASE] != nullptr)
        {
            leaseConfig.mMaxKeyLease = blobmsg_get_u32(tb[SET_SRP_MAX_KEY_LEASE]);
        }

        error = otSrpServerSetLeaseConfig(instance, &leaseConfig);
        if (error != OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "LeaseConfigError", otThreadErrorToString(error));
        }
    }

    // --- Auto-enable mode ---
    if (tb[SET_SRP_AUTO_ENABLE] != nullptr)
    {
        bool autoEnable = blobmsg_get_bool(tb[SET_SRP_AUTO_ENABLE]);
        otSrpServerSetAutoEnableMode(instance, autoEnable);
    }

    // --- Enable/Disable SRP server ---
    if (tb[SET_SRP_ENABLED] != nullptr)
    {
        bool enable = blobmsg_get_bool(tb[SET_SRP_ENABLED]);
        otSrpServerSetEnabled(instance, enable);
    }

    // --- Return current state after changes ---
    {
        otSrpServerState state = otSrpServerGetState(instance);
        const char *stateStr = "unknown";
        switch (state)
        {
        case OT_SRP_SERVER_STATE_DISABLED:
            stateStr = "disabled";
            break;
        case OT_SRP_SERVER_STATE_RUNNING:
            stateStr = "running";
            break;
        case OT_SRP_SERVER_STATE_STOPPED:
            stateStr = "stopped";
            break;
        }
        blobmsg_add_string(&mBuf, "State", stateStr);
    }

    {
        otSrpServerAddressMode mode = otSrpServerGetAddressMode(instance);
        blobmsg_add_string(&mBuf, "AddressMode",
                           (mode == OT_SRP_SERVER_ADDRESS_MODE_UNICAST) ? "unicast" : "anycast");
        blobmsg_add_u32(&mBuf, "AnycastSeq", otSrpServerGetAnycastModeSequenceNumber(instance));
    }

    blobmsg_add_u32(&mBuf, "Port", otSrpServerGetPort(instance));
    blobmsg_add_string(&mBuf, "Domain", otSrpServerGetDomain(instance));
    blobmsg_add_u8(&mBuf, "AutoEnable", otSrpServerIsAutoEnableMode(instance));

    {
        otSrpServerTtlConfig ttlConfig;
        otSrpServerGetTtlConfig(instance, &ttlConfig);
        void *ttlTable = blobmsg_open_table(&mBuf, "TtlConfig");
        blobmsg_add_u32(&mBuf, "MinTtl", ttlConfig.mMinTtl);
        blobmsg_add_u32(&mBuf, "MaxTtl", ttlConfig.mMaxTtl);
        blobmsg_close_table(&mBuf, ttlTable);
    }

    {
        otSrpServerLeaseConfig leaseConfig;
        otSrpServerGetLeaseConfig(instance, &leaseConfig);
        void *lcTable = blobmsg_open_table(&mBuf, "LeaseConfig");
        blobmsg_add_u32(&mBuf, "MinLease",     leaseConfig.mMinLease);
        blobmsg_add_u32(&mBuf, "MaxLease",     leaseConfig.mMaxLease);
        blobmsg_add_u32(&mBuf, "MinKeyLease", leaseConfig.mMinKeyLease);
        blobmsg_add_u32(&mBuf, "MaxKeyLease", leaseConfig.mMaxKeyLease);
        blobmsg_close_table(&mBuf, lcTable);
    }

    blobmsg_add_string(&mBuf, "Status", "success");

    otbrLogInfo("otbr-agent: SRP server config updated");
    AddEventLog("srp_server", "setsrpserver config updated");

    mNcpThreadMutex->unlock();
#else
    blobmsg_add_string(&mBuf, "Status", "unsupported");
    blobmsg_add_string(&mBuf, "Error", "srp_server_not_enabled");
#endif // OPENTHREAD_CONFIG_SRP_SERVER_ENABLE

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: setnat64config ===========================
// ubus call otbr-agent setnat64config '{"enabled":true,"cidr":"192.168.255.0/24","dns_upstream":true}'
// Sets NAT64/DNS64 configuration. All parameters are optional.
//   enabled      - enable/disable NAT64 (translator + prefix manager)
//   cidr         - IPv4 CIDR block for NAT64 translator (e.g. "192.168.255.0/24")
//   dns_upstream - enable/disable forwarding DNS queries to upstream (DNS64)

int UbusAgentExt::HandleSetNat64(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SetNat64Detail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetNat64Detail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest,
                                 struct blob_attr         *aMsg)
{
    blob_buf_init(&mBuf, 0);

    struct blob_attr *tb[SET_NAT64_MAX];

    if (aMsg != nullptr)
    {
        blobmsg_parse(setNat64Policy, SET_NAT64_MAX, tb, blob_data(aMsg), blob_len(aMsg));
    }
    else
    {
        memset(tb, 0, sizeof(tb));
    }

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // Helper lambda to convert NAT64 state to string
    auto nat64StateToStr = [](otNat64State aState) -> const char * {
        switch (aState)
        {
        case OT_NAT64_STATE_DISABLED:
            return "disabled";
        case OT_NAT64_STATE_NOT_RUNNING:
            return "not_running";
        case OT_NAT64_STATE_IDLE:
            return "idle";
        case OT_NAT64_STATE_ACTIVE:
            return "active";
        default:
            return "unknown";
        }
    };

#if OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE
    // --- Set IPv4 CIDR (do before enabling so translator can start with correct CIDR) ---
    if (tb[SET_NAT64_CIDR] != nullptr)
    {
        const char *cidrStr = blobmsg_get_string(tb[SET_NAT64_CIDR]);
        otIp4Cidr   cidr;
        otError     err = otIp4CidrFromString(cidrStr, &cidr);
        if (err == OT_ERROR_NONE)
        {
            err = otNat64SetIp4Cidr(instance, &cidr);
        }
        if (err != OT_ERROR_NONE)
        {
            blobmsg_add_string(&mBuf, "CidrError", otThreadErrorToString(err));
        }
    }
#endif // OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE

#if OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE || OPENTHREAD_CONFIG_NAT64_BORDER_ROUTING_ENABLE
    // --- Enable/Disable NAT64 ---
    if (tb[SET_NAT64_ENABLED] != nullptr)
    {
        bool enable = blobmsg_get_bool(tb[SET_NAT64_ENABLED]);
        otNat64SetEnabled(instance, enable);
        blobmsg_add_u8(&mBuf, "Enabled", enable);
    }
#endif

#if OPENTHREAD_CONFIG_DNS_UPSTREAM_QUERY_ENABLE
    // --- Enable/Disable DNS upstream query (DNS64) ---
    if (tb[SET_NAT64_DNS_UPSTREAM] != nullptr)
    {
        bool dnsUpstream = blobmsg_get_bool(tb[SET_NAT64_DNS_UPSTREAM]);
        otDnssdUpstreamQuerySetEnabled(instance, dnsUpstream);
        blobmsg_add_u8(&mBuf, "DnsUpstream", dnsUpstream);
    }
#endif // OPENTHREAD_CONFIG_DNS_UPSTREAM_QUERY_ENABLE

    // --- Return current state after changes ---
#if OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE
    {
        otNat64State translatorState = otNat64GetTranslatorState(instance);
        blobmsg_add_string(&mBuf, "TranslatorState", nat64StateToStr(translatorState));

        otIp4Cidr cidr;
        if (otNat64GetCidr(instance, &cidr) == OT_ERROR_NONE)
        {
            char cidrStr[OT_IP4_CIDR_STRING_SIZE];
            otIp4CidrToString(&cidr, cidrStr, sizeof(cidrStr));
            blobmsg_add_string(&mBuf, "Ipv4Cidr", cidrStr);
        }
        else
        {
            blobmsg_add_string(&mBuf, "Ipv4Cidr", "not_configured");
        }
    }
#else
    blobmsg_add_string(&mBuf, "TranslatorState", "not_compiled");
#endif

#if OPENTHREAD_CONFIG_NAT64_BORDER_ROUTING_ENABLE
    {
        otNat64State pmState = otNat64GetPrefixManagerState(instance);
        blobmsg_add_string(&mBuf, "PrefixManagerState", nat64StateToStr(pmState));

        otIp6Prefix nat64Prefix;
        if (otBorderRoutingGetNat64Prefix(instance, &nat64Prefix) == OT_ERROR_NONE)
        {
            char prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&nat64Prefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Nat64Prefix", prefixStr);
        }
    }
#else
    blobmsg_add_string(&mBuf, "PrefixManagerState", "not_compiled");
#endif

#if OPENTHREAD_CONFIG_DNS_UPSTREAM_QUERY_ENABLE
    blobmsg_add_u8(&mBuf, "DnsUpstreamEnabled", otDnssdUpstreamQueryIsEnabled(instance));
#else
    blobmsg_add_string(&mBuf, "DnsUpstream", "not_compiled");
#endif

    blobmsg_add_string(&mBuf, "Status", "success");

    otbrLogInfo("otbr-agent: NAT64/DNS64 config updated");
    AddEventLog("nat64", "setnat64config config updated");

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: omrprefix ==========================
// ubus call otbr-agent omrprefix
// Returns OMR (Off-Mesh-Routable) prefix information, equivalent to CLI "br omrprefix":
//   - local: the local OMR prefix generated by this BR
//   - favored: the currently favored OMR prefix in the network (with preference)
//   - pd: the DHCPv6 PD provided OMR prefix (if available)

int UbusAgentExt::HandleOmrPrefix(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
                                  struct ubus_request_data *aRequest,
                                  const char               *aMethod,
                                  struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().OmrPrefixDetail(aContext, aRequest);
}

int UbusAgentExt::OmrPrefixDetail(struct ubus_context      *aContext,
                                  struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    auto preferenceToStr = [](otRoutePreference aPref) -> const char * {
        switch (aPref)
        {
        case OT_ROUTE_PREFERENCE_LOW:
            return "low";
        case OT_ROUTE_PREFERENCE_MED:
            return "med";
        case OT_ROUTE_PREFERENCE_HIGH:
            return "high";
        default:
            return "unknown";
        }
    };

#if OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE
    // --- Local OMR prefix ---
    {
        otIp6Prefix localPrefix;
        otError     err = otBorderRoutingGetOmrPrefix(instance, &localPrefix);
        if (err == OT_ERROR_NONE)
        {
            void *localTable = blobmsg_open_table(&mBuf, "Local");
            char  prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&localPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_close_table(&mBuf, localTable);
        }
        else
        {
            blobmsg_add_string(&mBuf, "LocalError", otThreadErrorToString(err));
        }
    }

    // --- Favored OMR prefix ---
    {
        otIp6Prefix       favoredPrefix;
        otRoutePreference preference;
        otError           err = otBorderRoutingGetFavoredOmrPrefix(instance, &favoredPrefix, &preference);
        if (err == OT_ERROR_NONE)
        {
            void *favoredTable = blobmsg_open_table(&mBuf, "Favored");
            char  prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&favoredPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_add_string(&mBuf, "Preference", preferenceToStr(preference));
            blobmsg_close_table(&mBuf, favoredTable);
        }
        else
        {
            blobmsg_add_string(&mBuf, "FavoredError", otThreadErrorToString(err));
        }
    }

#if OPENTHREAD_CONFIG_BORDER_ROUTING_DHCP6_PD_ENABLE
    // --- PD (DHCPv6 Prefix Delegation) OMR prefix ---
    {
        otBorderRoutingPrefixTableEntry pdEntry;
        otError err = otBorderRoutingGetPdOmrPrefix(instance, &pdEntry);
        if (err == OT_ERROR_NONE)
        {
            void *pdTable = blobmsg_open_table(&mBuf, "Pd");
            char  prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&pdEntry.mPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_add_u32(&mBuf, "ValidLifetime", pdEntry.mValidLifetime);
            blobmsg_add_u32(&mBuf, "PreferredLifetime", pdEntry.mPreferredLifetime);
            blobmsg_close_table(&mBuf, pdTable);
        }
    }
#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_DHCP6_PD_ENABLE

#else
    blobmsg_add_string(&mBuf, "Error", "border_routing_not_enabled");
#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: onlinkprefix =======================
// ubus call otbr-agent onlinkprefix
// Returns On-Link prefix information, equivalent to CLI "br onlinkprefix":
//   - local: the local on-link prefix advertised by this BR on the infrastructure link
//   - favored: the currently favored on-link prefix discovered on the infrastructure link

int UbusAgentExt::HandleOnLinkPrefix(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
                                     struct ubus_request_data *aRequest,
                                     const char               *aMethod,
                                     struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().OnLinkPrefixDetail(aContext, aRequest);
}

int UbusAgentExt::OnLinkPrefixDetail(struct ubus_context      *aContext,
                                     struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

#if OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE
    // --- Local On-Link prefix ---
    {
        otIp6Prefix localPrefix;
        otError     err = otBorderRoutingGetOnLinkPrefix(instance, &localPrefix);
        if (err == OT_ERROR_NONE)
        {
            void *localTable = blobmsg_open_table(&mBuf, "Local");
            char  prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&localPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_close_table(&mBuf, localTable);
        }
        else
        {
            blobmsg_add_string(&mBuf, "LocalError", otThreadErrorToString(err));
        }
    }

    // --- Favored On-Link prefix ---
    {
        otIp6Prefix favoredPrefix;
        otError     err = otBorderRoutingGetFavoredOnLinkPrefix(instance, &favoredPrefix);
        if (err == OT_ERROR_NONE)
        {
            void *favoredTable = blobmsg_open_table(&mBuf, "Favored");
            char  prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&favoredPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_close_table(&mBuf, favoredTable);
        }
        else
        {
            blobmsg_add_string(&mBuf, "FavoredError", otThreadErrorToString(err));
        }
    }
#else
    blobmsg_add_string(&mBuf, "Error", "border_routing_not_enabled");
#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ============== MeshDiag Handler ==============================
// ubus call otbr-agent meshdiag
// ubus call otbr-agent meshdiag '{"ip6_addrs":true,"children":true,"childtable":true,"childip6":true,"routerneighbortable":true}'
//

// ================ Handler: commissionerstate ==================
// ubus call otbr-agent commissionerstate
// Returns: commissioner state and auto-stop timeout remaining seconds

int UbusAgentExt::HandleCommissionerstate(struct ubus_context      *aContext,
                                          struct ubus_object       *aObj,
                                          struct ubus_request_data *aRequest,
                                          const char               *aMethod,
                                          struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().CommissionerstateDetail(aContext, aRequest);
}

int UbusAgentExt::CommissionerstateDetail(struct ubus_context      *aContext,
                                          struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otCommissionerState state = otCommissionerGetState(instance);
    const char *stateStr = "disabled";
    switch (state)
    {
    case OT_COMMISSIONER_STATE_DISABLED:
        stateStr = "disabled";
        break;
    case OT_COMMISSIONER_STATE_PETITION:
        stateStr = "petition";
        break;
    case OT_COMMISSIONER_STATE_ACTIVE:
        stateStr = "active";
        break;
    }
    blobmsg_add_string(&mBuf, "State", stateStr);
    blobmsg_add_u32(&mBuf, "StateCode", state);

    int timeoutRemainingMs = uloop_timeout_remaining(&mCommissionerTimeoutTimer);
    uint32_t timeoutRemainingSec = 0;
    if (timeoutRemainingMs > 0)
    {
        timeoutRemainingSec = (timeoutRemainingMs + 999) / 1000;
    }
    blobmsg_add_u32(&mBuf, "TimeoutRemaining", timeoutRemainingSec);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: srpsrvconfig =======================
// ubus call otbr-agent srpsrvconfig
// Returns: SRP server configuration

int UbusAgentExt::HandleSrpsrvconfig(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
                                     struct ubus_request_data *aRequest,
                                     const char               *aMethod,
                                     struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().SrpsrvconfigDetail(aContext, aRequest);
}

int UbusAgentExt::SrpsrvconfigDetail(struct ubus_context      *aContext,
                                     struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
    // --- Server state ---
    {
        otSrpServerState state = otSrpServerGetState(instance);
        const char *stateStr = "unknown";
        switch (state)
        {
        case OT_SRP_SERVER_STATE_DISABLED:
            stateStr = "disabled";
            break;
        case OT_SRP_SERVER_STATE_RUNNING:
            stateStr = "running";
            break;
        case OT_SRP_SERVER_STATE_STOPPED:
            stateStr = "stopped";
            break;
        }
        blobmsg_add_string(&mBuf, "State", stateStr);
    }

    // --- Address mode ---
    {
        otSrpServerAddressMode mode = otSrpServerGetAddressMode(instance);
        const char *modeStr = (mode == OT_SRP_SERVER_ADDRESS_MODE_UNICAST) ? "unicast" : "anycast";
        blobmsg_add_string(&mBuf, "AddressMode", modeStr);
    }

    // --- Port & Domain ---
    blobmsg_add_u32(&mBuf, "Port", otSrpServerGetPort(instance));
    blobmsg_add_string(&mBuf, "Domain", otSrpServerGetDomain(instance));

    // --- Lease config ---
    {
        otSrpServerLeaseConfig leaseConfig;
        otSrpServerGetLeaseConfig(instance, &leaseConfig);

        blobmsg_add_u32(&mBuf, "MinLease",     leaseConfig.mMinLease);
        blobmsg_add_u32(&mBuf, "MaxLease",     leaseConfig.mMaxLease);
        blobmsg_add_u32(&mBuf, "MinKeyLease", leaseConfig.mMinKeyLease);
        blobmsg_add_u32(&mBuf, "MaxKeyLease", leaseConfig.mMaxKeyLease);
    }

    // --- Response counters ---
    {
        const otSrpServerResponseCounters *respCounters = otSrpServerGetResponseCounters(instance);
        if (respCounters != nullptr)
        {
            void *rcTable = blobmsg_open_table(&mBuf, "ResponseCounters");
            blobmsg_add_u32(&mBuf, "Success",        respCounters->mSuccess);
            blobmsg_add_u32(&mBuf, "ServerFailure",  respCounters->mServerFailure);
            blobmsg_add_u32(&mBuf, "FormatError",    respCounters->mFormatError);
            blobmsg_add_u32(&mBuf, "NameExists",     respCounters->mNameExists);
            blobmsg_add_u32(&mBuf, "Refused",          respCounters->mRefused);
            blobmsg_add_u32(&mBuf, "Other",            respCounters->mOther);
            blobmsg_close_table(&mBuf, rcTable);
        }
    }

    // --- Legacy compatible fields (srpsrvconfig original) ---
    blobmsg_add_u8(&mBuf, "Enable", (otSrpServerGetState(instance) == OT_SRP_SERVER_STATE_RUNNING) ? 1 : 0);
    blobmsg_add_string(&mBuf, "DomainName", otSrpServerGetDomain(instance));
    blobmsg_add_u32(&mBuf, "SeqNum", otSrpServerGetAnycastModeSequenceNumber(instance));

    char address[OT_IP6_ADDRESS_STRING_SIZE];
    memset(address, 0, sizeof(address));
    otIp6AddressToString(otThreadGetMeshLocalEid(instance), address, sizeof(address));
    blobmsg_add_string(&mBuf, "IP6Address", address);
#else
    blobmsg_add_string(&mBuf, "State", "not_compiled");
#endif // OPENTHREAD_CONFIG_SRP_SERVER_ENABLE

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: srpsrvservice ======================
// ubus call otbr-agent srpsrvservice
// Returns: All services registered on the SRP server

int UbusAgentExt::HandleSrpsrvservice(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
                                      struct ubus_request_data *aRequest,
                                      const char               *aMethod,
                                      struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().SrpsrvserviceDetail(aContext, aRequest);
}

int UbusAgentExt::SrpsrvserviceDetail(struct ubus_context      *aContext,
                                      struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    const otSrpServerHost *host = nullptr;
    void *servicesArray = blobmsg_open_array(&mBuf, "Services");

    while ((host = otSrpServerGetNextHost(instance, host)) != nullptr)
    {
        const otSrpServerService *service = nullptr;

        while ((service = otSrpServerHostGetNextService(host, service)) != nullptr)
        {
            bool isDeleted = otSrpServerServiceIsDeleted(service);
            const char *instanceName = otSrpServerServiceGetInstanceName(service);

            void *serviceTable = blobmsg_open_table(&mBuf, nullptr);
            blobmsg_add_string(&mBuf, "InstanceName", instanceName);
            blobmsg_add_u8(&mBuf, "Deleted", isDeleted ? 1 : 0);

            if (!isDeleted)
            {
                otSrpServerLeaseInfo leaseInfo;
                otSrpServerServiceGetLeaseInfo(service, &leaseInfo);
                blobmsg_add_u32(&mBuf, "Lease", leaseInfo.mLease / 1000);
                blobmsg_add_u32(&mBuf, "KeyLease", leaseInfo.mKeyLease / 1000);

                // Subtypes
                char subtypes[512] = {0};
                bool hasSubType = false;
                char subLabel[OT_DNS_MAX_LABEL_SIZE];
                for (uint16_t index = 0;; index++)
                {
                    const char *subTypeName = otSrpServerServiceGetSubTypeServiceNameAt(service, index);
                    if (subTypeName == nullptr)
                    {
                        if (hasSubType && strlen(subtypes) > 0)
                        {
                            subtypes[strlen(subtypes) - 1] = '\0';
                        }
                        break;
                    }
                    else
                    {
                        otSrpServerParseSubTypeServiceName(subTypeName, subLabel, sizeof(subLabel));
                        strcat(subtypes, subLabel);
                        strcat(subtypes, ",");
                        hasSubType = true;
                    }
                }
                if (strlen(subtypes) > 0)
                {
                    blobmsg_add_string(&mBuf, "Subtypes", subtypes);
                }

                blobmsg_add_u32(&mBuf, "Port", otSrpServerServiceGetPort(service));
                blobmsg_add_u32(&mBuf, "Priority", otSrpServerServiceGetPriority(service));
                blobmsg_add_u32(&mBuf, "Weight", otSrpServerServiceGetWeight(service));
                blobmsg_add_u32(&mBuf, "Ttl", otSrpServerServiceGetTtl(service));

                // TXT data
                uint16_t txtDataLength;
                const uint8_t *txtData = otSrpServerServiceGetTxtData(service, &txtDataLength);
                if (txtDataLength > 0)
                {
                    otDnsTxtEntryIterator iterator;
                    otDnsInitTxtEntryIterator(&iterator, txtData, txtDataLength);
                    otDnsTxtEntry entry;

                    void *txtArray = blobmsg_open_array(&mBuf, "TXT");
                    while (otDnsGetNextTxtEntry(&iterator, &entry) == OT_ERROR_NONE)
                    {
                        char item[512] = {0};
                        if (entry.mKey != nullptr)
                        {
                            strcat(item, entry.mKey);
                            if (entry.mValue != nullptr && entry.mValueLength > 0)
                            {
                                strcat(item, "=");
                                strncat(item, (const char*)entry.mValue, entry.mValueLength);
                            }
                        }
                        blobmsg_add_string(&mBuf, nullptr, item);
                    }
                    blobmsg_close_array(&mBuf, txtArray);
                }

                blobmsg_add_string(&mBuf, "Host", otSrpServerHostGetFullName(host));

                // Address
                uint8_t addressesNum;
                const otIp6Address *addresses = otSrpServerHostGetAddresses(host, &addressesNum);
                if (addressesNum > 0)
                {
                    void *addrArray = blobmsg_open_array(&mBuf, "Address");
                    for (uint8_t i = 0; i < addressesNum; ++i)
                    {
                        char addrStr[OT_IP6_ADDRESS_STRING_SIZE];
                        otIp6AddressToString(&addresses[i], addrStr, sizeof(addrStr));
                        blobmsg_add_string(&mBuf, nullptr, addrStr);
                    }
                    blobmsg_close_array(&mBuf, addrArray);
                }
            }

            blobmsg_close_table(&mBuf, serviceTable);
        }
    }
    blobmsg_close_array(&mBuf, servicesArray);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: srpnetservice =======================
// ubus call otbr-agent srpnetservice '{"service":"_matter._tcp"}'
// Browses SRP services through the OpenThread DNS client (default domain: default.service.arpa.)

int UbusAgentExt::HandleSrpNetService(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
                                      struct ubus_request_data *aRequest,
                                      const char               *aMethod,
                                      struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SrpNetServiceDetail(aContext, aRequest, aMsg);
}

static bool IsPrintableTxtValue(const uint8_t *aValue, uint16_t aLength)
{
    for (uint16_t i = 0; i < aLength; i++)
    {
        if (!isprint(aValue[i]))
        {
            return false;
        }
    }

    return true;
}

static std::string TxtValueToHex(const uint8_t *aValue, uint16_t aLength)
{
    static const char kHex[] = "0123456789abcdef";
    std::string       hex;

    hex.reserve(aLength * 2 + 2);
    hex.push_back('<');
    for (uint16_t i = 0; i < aLength; i++)
    {
        hex.push_back(kHex[(aValue[i] >> 4) & 0x0f]);
        hex.push_back(kHex[aValue[i] & 0x0f]);
    }
    hex.push_back('>');

    return hex;
}

static std::string FormatTxtEntry(const otDnsTxtEntry &aEntry)
{
    std::string item;

    if (aEntry.mKey != nullptr)
    {
        item = aEntry.mKey;
        if (aEntry.mValue != nullptr && aEntry.mValueLength > 0)
        {
            item.push_back('=');
            if (IsPrintableTxtValue(aEntry.mValue, aEntry.mValueLength))
            {
                item.append(reinterpret_cast<const char *>(aEntry.mValue), aEntry.mValueLength);
            }
            else
            {
                item.append(TxtValueToHex(aEntry.mValue, aEntry.mValueLength));
            }
        }
    }
    else if (aEntry.mValue != nullptr && aEntry.mValueLength > 0)
    {
        if (IsPrintableTxtValue(aEntry.mValue, aEntry.mValueLength))
        {
            item.assign(reinterpret_cast<const char *>(aEntry.mValue), aEntry.mValueLength);
        }
        else
        {
            item = TxtValueToHex(aEntry.mValue, aEntry.mValueLength);
        }
    }

    return item;
}

static std::string ExtractExtAddrFromDnsHost(const char *aHostName)
{
    if (aHostName == nullptr)
    {
        return "";
    }

    std::string host(aHostName);
    size_t      dot = host.find('.');
    std::string label = (dot == std::string::npos) ? host : host.substr(0, dot);

    if (label.size() != OT_EXT_ADDRESS_SIZE * 2)
    {
        return "";
    }

    for (char c : label)
    {
        if (!isxdigit(static_cast<unsigned char>(c)))
        {
            return "";
        }
    }

    std::transform(label.begin(), label.end(), label.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return label;
}

int UbusAgentExt::SrpNetServiceDetail(struct ubus_context      *aContext,
                                      struct ubus_request_data *aRequest,
                                      struct blob_attr         *aMsg)
{
    struct blob_attr *tb[SRPNETSERVICE_MAX];
    const char       *service = nullptr;
    const char       *domain  = "default.service.arpa.";

    memset(tb, 0, sizeof(tb));
    blob_buf_init(&mBuf, 0);

    if (aMsg != nullptr)
    {
        blobmsg_parse(srpNetServicePolicy, SRPNETSERVICE_MAX, tb, blob_data(aMsg), blob_len(aMsg));
    }

    if (tb[SRPNETSERVICE_SERVICE] != nullptr)
    {
        service = blobmsg_get_string(tb[SRPNETSERVICE_SERVICE]);
    }
    if (tb[SRPNETSERVICE_DOMAIN] != nullptr)
    {
        domain = blobmsg_get_string(tb[SRPNETSERVICE_DOMAIN]);
    }

    mNcpThreadMutex->lock();
    otDeviceRole role = otThreadGetDeviceRole(mController->GetInstance());
    mNcpThreadMutex->unlock();

    if (role != OT_DEVICE_ROLE_ROUTER && role != OT_DEVICE_ROLE_LEADER)
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_string(&mBuf, "Source", "openthread_dns_client");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *servicesArray = blobmsg_open_array(&mBuf, "Services");
        blobmsg_close_array(&mBuf, servicesArray);
        blobmsg_add_u32(&mBuf, "ServiceCount", 0);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    bool     resolve    = (tb[SRPNETSERVICE_RESOLVE] != nullptr) ? blobmsg_get_bool(tb[SRPNETSERVICE_RESOLVE]) : true;
    uint32_t timeoutSec = (tb[SRPNETSERVICE_TIMEOUT] != nullptr) ? blobmsg_get_u32(tb[SRPNETSERVICE_TIMEOUT]) : 2;
    uint8_t  attempts   = (tb[SRPNETSERVICE_ATTEMPTS] != nullptr) ? blobmsg_get_u32(tb[SRPNETSERVICE_ATTEMPTS]) : 1;

    if (timeoutSec == 0)
    {
        timeoutSec = 2;
    }
    if (attempts == 0)
    {
        attempts = 1;
    }

    if (domain == nullptr || domain[0] == '\0')
    {
        domain = "default.service.arpa.";
    }

    std::vector<std::string> serviceNames;
    if (service == nullptr || service[0] == '\0' || strcmp(service, "*") == 0)
    {
        char matterServiceName[OT_DNS_MAX_NAME_SIZE];
        char glinetServiceName[OT_DNS_MAX_NAME_SIZE];

        snprintf(matterServiceName, sizeof(matterServiceName), "_matter._tcp.%s%s", domain,
                 (domain[strlen(domain) - 1] == '.') ? "" : ".");
        snprintf(glinetServiceName, sizeof(glinetServiceName), "_glinet._tcp.%s%s", domain,
                 (domain[strlen(domain) - 1] == '.') ? "" : ".");

        serviceNames.push_back(matterServiceName);
        serviceNames.push_back(glinetServiceName);
    }
    else if (service[strlen(service) - 1] == '.')
    {
        serviceNames.push_back(service);
    }
    else
    {
        char serviceName[OT_DNS_MAX_NAME_SIZE];
        snprintf(serviceName, sizeof(serviceName), "%s.%s%s", service, domain,
                 (domain[strlen(domain) - 1] == '.') ? "" : ".");
        serviceNames.push_back(serviceName);
    }

    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (mSrpNetServiceBusy)
        {
            blobmsg_add_string(&mBuf, "Error", "busy");
            blobmsg_add_string(&mBuf, "Detail", "an srpnetservice operation is already in progress");
            ubus_send_reply(aContext, aRequest, mBuf.head);
            return 0;
        }

        mSrpNetServiceBusy       = true;
        mSrpNetServiceDone       = false;
        mSrpNetServiceResolve    = resolve;
        mSrpNetServiceResolveIdx = 0;
        mSrpNetServiceBrowseIdx  = 0;
        mSrpNetServiceFinalError = OT_ERROR_NONE;
        memset(&mSrpNetServiceQueryConfig, 0, sizeof(mSrpNetServiceQueryConfig));
        mSrpNetServiceQueryConfig.mResponseTimeout = timeoutSec * 1000;
        mSrpNetServiceQueryConfig.mMaxTxAttempts   = attempts;
        mSrpNetServiceNames      = serviceNames;
        mSrpNetServiceResults.clear();
    }

    otError error = StartNextSrpNetServiceBrowse();

    if (error != OT_ERROR_NONE)
    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        mSrpNetServiceBusy = false;
        mSrpNetServiceDone = false;

        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));
        blobmsg_add_u32(&mBuf, "ErrorCode", error);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    ubus_defer_request(aContext, aRequest, &mSrpNetServiceDeferredReq);
    mSrpNetServiceUbusCtx = aContext;

    return 0;
}

void UbusAgentExt::HandleSrpNetServiceBrowse(otError aError, const otDnsBrowseResponse *aResponse, void *aContext)
{
    reinterpret_cast<UbusAgentExt *>(aContext)->HandleSrpNetServiceBrowse(aError, aResponse);
}

void UbusAgentExt::HandleSrpNetServiceBrowse(otError aError, const otDnsBrowseResponse *aResponse)
{
    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (mSrpNetServiceFinalError == OT_ERROR_NONE && aError != OT_ERROR_NONE)
        {
            mSrpNetServiceFinalError = aError;
        }

        if (aError == OT_ERROR_NONE && mSrpNetServiceBrowseIdx < mSrpNetServiceNames.size())
        {
            const std::string serviceName = mSrpNetServiceNames[mSrpNetServiceBrowseIdx];
            for (uint16_t index = 0;; index++)
            {
                char label[OT_DNS_MAX_LABEL_SIZE];
                otError error = otDnsBrowseResponseGetServiceInstance(aResponse, index, label, sizeof(label));
                if (error == OT_ERROR_NOT_FOUND)
                {
                    break;
                }
                if (error == OT_ERROR_NONE)
                {
                    SrpNetServiceResult result;
                    memset(&result.mHostAddress, 0, sizeof(result.mHostAddress));
                    result.mInstance       = label;
                    result.mServiceName    = serviceName;
                    result.mError          = OT_ERROR_NONE;
                    result.mResolved       = false;
                    result.mTtl            = 0;
                    result.mPort           = 0;
                    result.mPriority       = 0;
                    result.mWeight         = 0;
                    result.mHostAddressTtl = 0;

                    char hostName[OT_DNS_MAX_NAME_SIZE];
                    uint8_t txtData[512];
                    otDnsServiceInfo info;
                    memset(&info, 0, sizeof(info));
                    memset(hostName, 0, sizeof(hostName));
                    info.mHostNameBuffer     = hostName;
                    info.mHostNameBufferSize = sizeof(hostName);
                    info.mTxtData            = txtData;
                    info.mTxtDataSize        = sizeof(txtData);
                    if (otDnsBrowseResponseGetServiceInfo(aResponse, label, &info) == OT_ERROR_NONE)
                    {
                        result.mResolved       = true;
                        result.mTtl            = info.mTtl;
                        result.mPort           = info.mPort;
                        result.mPriority       = info.mPriority;
                        result.mWeight         = info.mWeight;
                        result.mHost           = hostName;
                        result.mExtAddr        = ExtractExtAddrFromDnsHost(hostName);
                        result.mHostAddress    = info.mHostAddress;
                        result.mHostAddressTtl = info.mHostAddressTtl;

                        otDnsTxtEntryIterator iterator;
                        otDnsTxtEntry         entry;
                        otDnsInitTxtEntryIterator(&iterator, txtData, info.mTxtDataSize);
                        while (otDnsGetNextTxtEntry(&iterator, &entry) == OT_ERROR_NONE)
                        {
                            result.mTxt.push_back(FormatTxtEntry(entry));
                        }
                    }

                    mSrpNetServiceResults.push_back(std::move(result));
                }
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        mSrpNetServiceBrowseIdx++;
    }

    if (StartNextSrpNetServiceBrowse() == OT_ERROR_NONE)
    {
        return;
    }

    if (mSrpNetServiceResolve && StartNextSrpNetServiceResolve() == OT_ERROR_NONE)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
    mSrpNetServiceDone = true;
}

void UbusAgentExt::HandleSrpNetServiceResolve(otError aError, const otDnsServiceResponse *aResponse, void *aContext)
{
    reinterpret_cast<UbusAgentExt *>(aContext)->HandleSrpNetServiceResolve(aError, aResponse);
}

void UbusAgentExt::HandleSrpNetServiceResolve(otError aError, const otDnsServiceResponse *aResponse)
{
    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (mSrpNetServiceResolveIdx < mSrpNetServiceResults.size())
        {
            SrpNetServiceResult &result = mSrpNetServiceResults[mSrpNetServiceResolveIdx];
            result.mError = aError;

            if (aError == OT_ERROR_NONE)
            {
                char label[OT_DNS_MAX_LABEL_SIZE];
                char name[OT_DNS_MAX_NAME_SIZE];
                char hostName[OT_DNS_MAX_NAME_SIZE];
                uint8_t txtData[512];
                otDnsServiceInfo info;

                memset(label, 0, sizeof(label));
                memset(name, 0, sizeof(name));
                memset(hostName, 0, sizeof(hostName));
                memset(&info, 0, sizeof(info));
                info.mHostNameBuffer     = hostName;
                info.mHostNameBufferSize = sizeof(hostName);
                info.mTxtData            = txtData;
                info.mTxtDataSize        = sizeof(txtData);

                if (otDnsServiceResponseGetServiceName(aResponse, label, sizeof(label), name, sizeof(name)) == OT_ERROR_NONE)
                {
                    result.mInstance = label;
                }

                if (otDnsServiceResponseGetServiceInfo(aResponse, &info) == OT_ERROR_NONE)
                {
                    result.mResolved       = true;
                    result.mTtl            = info.mTtl;
                    result.mPort           = info.mPort;
                    result.mPriority       = info.mPriority;
                    result.mWeight         = info.mWeight;
                    result.mHost           = hostName;
                    result.mHostAddress    = info.mHostAddress;
                    result.mHostAddressTtl = info.mHostAddressTtl;
                    result.mTxt.clear();

                    otDnsTxtEntryIterator iterator;
                    otDnsTxtEntry         entry;
                    otDnsInitTxtEntryIterator(&iterator, txtData, info.mTxtDataSize);
                    while (otDnsGetNextTxtEntry(&iterator, &entry) == OT_ERROR_NONE)
                    {
                        result.mTxt.push_back(FormatTxtEntry(entry));
                    }
                }
            }
        }

        mSrpNetServiceResolveIdx++;
    }

    if (StartNextSrpNetServiceResolve() == OT_ERROR_NONE)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
    mSrpNetServiceDone = true;
}

otError UbusAgentExt::StartNextSrpNetServiceBrowse(void)
{
    std::string serviceName;

    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (mSrpNetServiceBrowseIdx >= mSrpNetServiceNames.size())
        {
            return OT_ERROR_NOT_FOUND;
        }
        serviceName = mSrpNetServiceNames[mSrpNetServiceBrowseIdx];
    }

    mNcpThreadMutex->lock();
    otError error = otDnsClientBrowse(mController->GetInstance(), serviceName.c_str(),
                                      &UbusAgentExt::HandleSrpNetServiceBrowse, this,
                                      &mSrpNetServiceQueryConfig);
    mNcpThreadMutex->unlock();

    if (error != OT_ERROR_NONE)
    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (mSrpNetServiceFinalError == OT_ERROR_NONE)
        {
            mSrpNetServiceFinalError = error;
        }
        mSrpNetServiceBrowseIdx++;
        return StartNextSrpNetServiceBrowse();
    }

    return OT_ERROR_NONE;
}

otError UbusAgentExt::StartNextSrpNetServiceResolve(void)
{
    std::string serviceName;
    std::string instance;

    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (!mSrpNetServiceResolve || mSrpNetServiceResolveIdx >= mSrpNetServiceResults.size())
        {
            return OT_ERROR_NOT_FOUND;
        }
        serviceName = mSrpNetServiceResults[mSrpNetServiceResolveIdx].mServiceName;
        instance    = mSrpNetServiceResults[mSrpNetServiceResolveIdx].mInstance;
    }

    mNcpThreadMutex->lock();
    otError error = otDnsClientResolveServiceAndHostAddress(mController->GetInstance(), instance.c_str(), serviceName.c_str(),
                                                            &UbusAgentExt::HandleSrpNetServiceResolve, this,
                                                            &mSrpNetServiceQueryConfig);
    mNcpThreadMutex->unlock();

    if (error != OT_ERROR_NONE)
    {
        std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);
        if (mSrpNetServiceResolveIdx < mSrpNetServiceResults.size())
        {
            mSrpNetServiceResults[mSrpNetServiceResolveIdx].mError = error;
            mSrpNetServiceResolveIdx++;
        }
        return StartNextSrpNetServiceResolve();
    }

    return OT_ERROR_NONE;
}

void UbusAgentExt::CompleteSrpNetServiceDeferred(void)
{
    std::lock_guard<std::mutex> lock(mSrpNetServiceMutex);

    if (!mSrpNetServiceBusy || !mSrpNetServiceDone || mSrpNetServiceUbusCtx == nullptr)
    {
        return;
    }

    struct blob_buf b;
    memset(&b, 0, sizeof(b));
    blob_buf_init(&b, 0);

    blobmsg_add_string(&b, "Source", "openthread_dns_client");
    blobmsg_add_u32(&b, "Timeout", mSrpNetServiceQueryConfig.mResponseTimeout / 1000);
    blobmsg_add_u32(&b, "Attempts", mSrpNetServiceQueryConfig.mMaxTxAttempts);
    void *serviceTypesArray = blobmsg_open_array(&b, "ServiceTypes");
    for (const auto &serviceName : mSrpNetServiceNames)
    {
        blobmsg_add_string(&b, nullptr, serviceName.c_str());
    }
    blobmsg_close_array(&b, serviceTypesArray);
    blobmsg_add_u32(&b, "ErrorCode", mSrpNetServiceFinalError);
    if (mSrpNetServiceFinalError != OT_ERROR_NONE)
    {
        blobmsg_add_string(&b, "Error", otThreadErrorToString(mSrpNetServiceFinalError));
    }

    void *servicesArray = blobmsg_open_array(&b, "Services");
    char addrStr[OT_IP6_ADDRESS_STRING_SIZE];
    for (const auto &service : mSrpNetServiceResults)
    {
        void *entry = blobmsg_open_table(&b, nullptr);
        blobmsg_add_string(&b, "InstanceName", service.mInstance.c_str());
        blobmsg_add_string(&b, "ServiceName", service.mServiceName.c_str());
        blobmsg_add_u8(&b, "Resolved", service.mResolved ? 1 : 0);
        blobmsg_add_u32(&b, "ErrorCode", service.mError);
        if (service.mError != OT_ERROR_NONE)
        {
            blobmsg_add_string(&b, "Error", otThreadErrorToString(service.mError));
        }
        if (service.mResolved)
        {
            blobmsg_add_u32(&b, "Port", service.mPort);
            blobmsg_add_u32(&b, "Priority", service.mPriority);
            blobmsg_add_u32(&b, "Weight", service.mWeight);
            blobmsg_add_u32(&b, "Ttl", service.mTtl);
            blobmsg_add_string(&b, "Host", service.mHost.c_str());
            if (!service.mExtAddr.empty())
            {
                blobmsg_add_string(&b, "ExtAddr", service.mExtAddr.c_str());
            }

            if (!otIp6IsAddressUnspecified(&service.mHostAddress))
            {
                otIp6AddressToString(&service.mHostAddress, addrStr, sizeof(addrStr));
                blobmsg_add_string(&b, "HostAddress", addrStr);
                blobmsg_add_u32(&b, "HostAddressTtl", service.mHostAddressTtl);
            }

            void *txtArray = blobmsg_open_array(&b, "TXT");
            for (const auto &txt : service.mTxt)
            {
                blobmsg_add_string(&b, nullptr, txt.c_str());
            }
            blobmsg_close_array(&b, txtArray);
        }
        blobmsg_close_table(&b, entry);
    }
    blobmsg_close_array(&b, servicesArray);
    blobmsg_add_u32(&b, "ServiceCount", mSrpNetServiceResults.size());

    ubus_send_reply(mSrpNetServiceUbusCtx, &mSrpNetServiceDeferredReq, b.head);
    ubus_complete_deferred_request(mSrpNetServiceUbusCtx, &mSrpNetServiceDeferredReq, 0);
    blob_buf_free(&b);

    mSrpNetServiceUbusCtx = nullptr;
    mSrpNetServiceBusy = false;
    mSrpNetServiceDone = false;
    mSrpNetServiceNames.clear();
    mSrpNetServiceResults.clear();
}

// ================ Handler: services ===========================
// ubus call otbr-agent services
// Returns: Network services (BBR, SRP server, etc.)

int UbusAgentExt::HandleServices(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().ServicesDetail(aContext, aRequest);
}

int UbusAgentExt::ServicesDetail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otDeviceRole role = otThreadGetDeviceRole(instance);

    if (!IsThreadAttachedRole(role))
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *servicesArray = blobmsg_open_array(&mBuf, "services");
        blobmsg_close_array(&mBuf, servicesArray);
        mNcpThreadMutex->unlock();
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
    otServiceConfig config;

    void *servicesArray = blobmsg_open_array(&mBuf, "services");

    while (otNetDataGetNextService(instance, &iterator, &config) == OT_ERROR_NONE)
    {
        void *serviceTable = blobmsg_open_table(&mBuf, nullptr);

        blobmsg_add_u16(&mBuf, "ServiceId", config.mServiceId);
        blobmsg_add_u32(&mBuf, "EnterpriseNumber", config.mEnterpriseNumber);
        blobmsg_add_u16(&mBuf, "ServiceDataLength", config.mServiceDataLength);

        char serviceDataStr[128] = {0};
        OutputBytes(config.mServiceData, config.mServiceDataLength, serviceDataStr);
        blobmsg_add_string(&mBuf, "ServiceData", serviceDataStr);

        // Identify service type
        if (config.mServiceDataLength == 1 && config.mServiceData[0] == 0x01)
        {
            blobmsg_add_string(&mBuf, "ServiceName", "BBR");
        }
        else if (config.mServiceDataLength == 1 && config.mServiceData[0] == 0x5d)
        {
            blobmsg_add_string(&mBuf, "ServiceName", "SRP server");
        }

        blobmsg_add_u16(&mBuf, "ServerDataLength", config.mServerConfig.mServerDataLength);
        char serverDataStr[128] = {0};
        OutputBytes(config.mServerConfig.mServerData, config.mServerConfig.mServerDataLength, serverDataStr);
        blobmsg_add_string(&mBuf, "ServerData", serverDataStr);
        blobmsg_add_u8(&mBuf, "Stable", config.mServerConfig.mStable ? 1 : 0);
        blobmsg_add_u32(&mBuf, "Rloc16", config.mServerConfig.mRloc16);

        blobmsg_close_table(&mBuf, serviceTable);
    }
    blobmsg_close_array(&mBuf, servicesArray);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: netdata ============================
// ubus call otbr-agent netdata
// Returns: Thread Network Data grouped like `ot-ctl netdata show`

int UbusAgentExt::HandleNetdata(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
                                struct ubus_request_data *aRequest,
                                const char               *aMethod,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().NetdataDetail(aContext, aRequest);
}

int UbusAgentExt::NetdataDetail(struct ubus_context      *aContext,
                                struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otDeviceRole role = otThreadGetDeviceRole(instance);

    if (!IsThreadAttachedRole(role))
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *prefixes = blobmsg_open_array(&mBuf, "Prefixes");
        blobmsg_close_array(&mBuf, prefixes);
        void *routes = blobmsg_open_array(&mBuf, "Routes");
        blobmsg_close_array(&mBuf, routes);
        void *services = blobmsg_open_array(&mBuf, "Services");
        blobmsg_close_array(&mBuf, services);
        void *contexts = blobmsg_open_array(&mBuf, "Contexts");
        blobmsg_close_array(&mBuf, contexts);
        mNcpThreadMutex->unlock();
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    {
        otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
        otBorderRouterConfig  config;
        void                 *prefixes = blobmsg_open_array(&mBuf, "Prefixes");

        while (otNetDataGetNextOnMeshPrefix(instance, &iterator, &config) == OT_ERROR_NONE)
        {
            char        prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            char        line[OT_IP6_PREFIX_STRING_SIZE + 64];
            std::string flags = NetDataPrefixFlagsToString(config);
            void       *entry = blobmsg_open_table(&mBuf, nullptr);

            otIp6PrefixToString(&config.mPrefix, prefixStr, sizeof(prefixStr));

            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_add_string(&mBuf, "Flags", flags.c_str());
            blobmsg_add_string(&mBuf, "Preference", NetDataPreferenceToString(config.mPreference));
            AddRloc16ToBlob(&mBuf, "Rloc16", config.mRloc16);
            AddBlobMsgBool(&mBuf, "Preferred", config.mPreferred);
            AddBlobMsgBool(&mBuf, "Slaac", config.mSlaac);
            AddBlobMsgBool(&mBuf, "Dhcp", config.mDhcp);
            AddBlobMsgBool(&mBuf, "Configure", config.mConfigure);
            AddBlobMsgBool(&mBuf, "DefaultRoute", config.mDefaultRoute);
            AddBlobMsgBool(&mBuf, "OnMesh", config.mOnMesh);
            AddBlobMsgBool(&mBuf, "Stable", config.mStable);
            AddBlobMsgBool(&mBuf, "NdDns", config.mNdDns);
            AddBlobMsgBool(&mBuf, "DomainPrefix", config.mDp);

            snprintf(line, sizeof(line), "%s %s %s %04x", prefixStr, flags.c_str(),
                     NetDataPreferenceToString(config.mPreference), config.mRloc16);
            blobmsg_add_string(&mBuf, "Cli", line);

            blobmsg_close_table(&mBuf, entry);
        }

        blobmsg_close_array(&mBuf, prefixes);
    }

    {
        otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
        otExternalRouteConfig config;
        void                 *routes = blobmsg_open_array(&mBuf, "Routes");

        while (otNetDataGetNextRoute(instance, &iterator, &config) == OT_ERROR_NONE)
        {
            char        prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            char        line[OT_IP6_PREFIX_STRING_SIZE + 64];
            std::string flags = NetDataRouteFlagsToString(config);
            void       *entry = blobmsg_open_table(&mBuf, nullptr);

            otIp6PrefixToString(&config.mPrefix, prefixStr, sizeof(prefixStr));

            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_add_string(&mBuf, "Flags", flags.c_str());
            blobmsg_add_string(&mBuf, "Preference", NetDataPreferenceToString(config.mPreference));
            AddRloc16ToBlob(&mBuf, "Rloc16", config.mRloc16);
            AddBlobMsgBool(&mBuf, "Stable", config.mStable);
            AddBlobMsgBool(&mBuf, "Nat64", config.mNat64);
            AddBlobMsgBool(&mBuf, "AdvPio", config.mAdvPio);
            AddBlobMsgBool(&mBuf, "NextHopIsThisDevice", config.mNextHopIsThisDevice);

            snprintf(line, sizeof(line), "%s %s %s %04x", prefixStr, flags.c_str(),
                     NetDataPreferenceToString(config.mPreference), config.mRloc16);
            blobmsg_add_string(&mBuf, "Cli", line);

            blobmsg_close_table(&mBuf, entry);
        }

        blobmsg_close_array(&mBuf, routes);
    }

    {
        otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
        otServiceConfig       config;
        void                 *services = blobmsg_open_array(&mBuf, "Services");

        while (otNetDataGetNextService(instance, &iterator, &config) == OT_ERROR_NONE)
        {
            char        serviceDataStr[OT_SERVICE_DATA_MAX_SIZE * 2 + 1] = {0};
            char        serverDataStr[OT_SERVER_DATA_MAX_SIZE * 2 + 1]   = {0};
            char        line[(OT_SERVICE_DATA_MAX_SIZE + OT_SERVER_DATA_MAX_SIZE) * 2 + 64];
            const char *serviceName = NetDataServiceName(config);
            void       *entry       = blobmsg_open_table(&mBuf, nullptr);

            OutputBytes(config.mServiceData, config.mServiceDataLength, serviceDataStr);
            OutputBytes(config.mServerConfig.mServerData, config.mServerConfig.mServerDataLength, serverDataStr);

            blobmsg_add_u16(&mBuf, "ServiceId", config.mServiceId);
            blobmsg_add_u32(&mBuf, "EnterpriseNumber", config.mEnterpriseNumber);
            blobmsg_add_u16(&mBuf, "ServiceDataLength", config.mServiceDataLength);
            blobmsg_add_string(&mBuf, "ServiceData", serviceDataStr);
            if (serviceName != nullptr)
            {
                blobmsg_add_string(&mBuf, "ServiceName", serviceName);
            }
            blobmsg_add_u16(&mBuf, "ServerDataLength", config.mServerConfig.mServerDataLength);
            blobmsg_add_string(&mBuf, "ServerData", serverDataStr);
            AddBlobMsgBool(&mBuf, "Stable", config.mServerConfig.mStable);
            AddRloc16ToBlob(&mBuf, "Rloc16", config.mServerConfig.mRloc16);

            snprintf(line, sizeof(line), "%lu %s %s%s %04x",
                     static_cast<unsigned long>(config.mEnterpriseNumber), serviceDataStr, serverDataStr,
                     config.mServerConfig.mStable ? " s" : "", config.mServerConfig.mRloc16);
            blobmsg_add_string(&mBuf, "Cli", line);

            blobmsg_close_table(&mBuf, entry);
        }

        blobmsg_close_array(&mBuf, services);
    }

    {
        otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
        otLowpanContextInfo   context;
        void                 *contexts = blobmsg_open_array(&mBuf, "Contexts");

        while (otNetDataGetNextLowpanContextInfo(instance, &iterator, &context) == OT_ERROR_NONE)
        {
            char  prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            char  line[OT_IP6_PREFIX_STRING_SIZE + 16];
            void *entry = blobmsg_open_table(&mBuf, nullptr);

            otIp6PrefixToString(&context.mPrefix, prefixStr, sizeof(prefixStr));

            blobmsg_add_string(&mBuf, "Prefix", prefixStr);
            blobmsg_add_u32(&mBuf, "ContextId", context.mContextId);
            AddBlobMsgBool(&mBuf, "Compress", context.mCompressFlag);
            blobmsg_add_string(&mBuf, "Flags", context.mCompressFlag ? "c" : "-");

            snprintf(line, sizeof(line), "%s %u %c", prefixStr, context.mContextId,
                     context.mCompressFlag ? 'c' : '-');
            blobmsg_add_string(&mBuf, "Cli", line);

            blobmsg_close_table(&mBuf, entry);
        }

        blobmsg_close_array(&mBuf, contexts);
    }

    {
        otCommissioningDataset dataset;
        char                   steeringDataStr[OT_STEERING_DATA_MAX_LENGTH * 2 + 1] = {0};
        char                   locatorStr[16] = "-";
        char                   line[128];
        void                  *commissioning;

        memset(&dataset, 0, sizeof(dataset));
        otNetDataGetCommissioningDataset(instance, &dataset);

        if (dataset.mIsSteeringDataSet)
        {
            OutputBytes(dataset.mSteeringData.m8, dataset.mSteeringData.mLength, steeringDataStr);
        }

        if (dataset.mIsLocatorSet)
        {
            snprintf(locatorStr, sizeof(locatorStr), "%04x", dataset.mLocator);
        }

        commissioning = blobmsg_open_table(&mBuf, "Commissioning");
        AddBlobMsgBool(&mBuf, "IsSessionIdSet", dataset.mIsSessionIdSet);
        AddBlobMsgBool(&mBuf, "IsLocatorSet", dataset.mIsLocatorSet);
        AddBlobMsgBool(&mBuf, "IsJoinerUdpPortSet", dataset.mIsJoinerUdpPortSet);
        AddBlobMsgBool(&mBuf, "IsSteeringDataSet", dataset.mIsSteeringDataSet);
        AddBlobMsgBool(&mBuf, "HasExtraTlv", dataset.mHasExtraTlv);

        if (dataset.mIsSessionIdSet)
        {
            blobmsg_add_u32(&mBuf, "SessionId", dataset.mSessionId);
        }
        if (dataset.mIsLocatorSet)
        {
            AddRloc16ToBlob(&mBuf, "Locator", dataset.mLocator);
        }
        if (dataset.mIsJoinerUdpPortSet)
        {
            blobmsg_add_u32(&mBuf, "JoinerUdpPort", dataset.mJoinerUdpPort);
        }
        if (dataset.mIsSteeringDataSet)
        {
            blobmsg_add_string(&mBuf, "SteeringData", steeringDataStr);
        }

        snprintf(line, sizeof(line), "%s%s %s %s %s%s",
                 dataset.mIsSessionIdSet ? std::to_string(dataset.mSessionId).c_str() : "-",
                 "",
                 dataset.mIsLocatorSet ? locatorStr : "-",
                 dataset.mIsJoinerUdpPortSet ? std::to_string(dataset.mJoinerUdpPort).c_str() : "-",
                 dataset.mIsSteeringDataSet ? steeringDataStr : "-",
                 dataset.mHasExtraTlv ? " e" : "");
        blobmsg_add_string(&mBuf, "Cli", line);
        blobmsg_close_table(&mBuf, commissioning);
    }

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: neighbortable ======================
// ubus call otbr-agent neighbortable
// Returns: Neighbor table information

int UbusAgentExt::HandleNeighbortable(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
                                      struct ubus_request_data *aRequest,
                                      const char               *aMethod,
                                      struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().NeighbortableDetail(aContext, aRequest);
}

int UbusAgentExt::NeighbortableDetail(struct ubus_context      *aContext,
                                      struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otDeviceRole role = otThreadGetDeviceRole(instance);

    if (!IsThreadAttachedRole(role))
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *neighborArray = blobmsg_open_array(&mBuf, "neighbors");
        blobmsg_close_array(&mBuf, neighborArray);
        blobmsg_add_u32(&mBuf, "NeighborCount", 0);
        mNcpThreadMutex->unlock();
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    otNeighborInfo neighborInfo;
    otNeighborInfoIterator iterator = OT_NEIGHBOR_INFO_ITERATOR_INIT;
    uint16_t neighborCount = 0;

    void *neighborArray = blobmsg_open_array(&mBuf, "neighbors");

    while (otThreadGetNextNeighborInfo(instance, &iterator, &neighborInfo) == OT_ERROR_NONE)
    {
        void *neighborTable = blobmsg_open_table(&mBuf, nullptr);

        char extAddress[32] = "";
        OutputBytes(neighborInfo.mExtAddress.m8, sizeof(neighborInfo.mExtAddress.m8), extAddress);
        blobmsg_add_string(&mBuf, "ExtAddr", extAddress);

        blobmsg_add_u32(&mBuf, "Age", neighborInfo.mAge);
        blobmsg_add_u32(&mBuf, "Rloc16", neighborInfo.mRloc16);
        blobmsg_add_u32(&mBuf, "LinkFrameCounter", neighborInfo.mLinkFrameCounter);
        blobmsg_add_u32(&mBuf, "MleFrameCounter", neighborInfo.mMleFrameCounter);
        blobmsg_add_u32(&mBuf, "LinkQualityIn", neighborInfo.mLinkQualityIn);
        blobmsg_add_u32(&mBuf, "AvgRssi", neighborInfo.mAverageRssi);
        blobmsg_add_u32(&mBuf, "LastRssi", neighborInfo.mLastRssi);
        blobmsg_add_u32(&mBuf, "LinkMargin", neighborInfo.mLinkMargin);
        blobmsg_add_u32(&mBuf, "FrameErrorRate", neighborInfo.mFrameErrorRate);
        blobmsg_add_u32(&mBuf, "MessageErrorRate", neighborInfo.mMessageErrorRate);
        blobmsg_add_u32(&mBuf, "Version", neighborInfo.mVersion);

        // Mode flags
        void *modeTable = blobmsg_open_table(&mBuf, "Mode");
        blobmsg_add_u32(&mBuf, "RxOnWhenIdle", neighborInfo.mRxOnWhenIdle ? 1 : 0);
        blobmsg_add_u32(&mBuf, "DeviceType", neighborInfo.mFullThreadDevice ? 1 : 0);
        blobmsg_add_u32(&mBuf, "NetworkData", neighborInfo.mFullNetworkData ? 1 : 0);
        blobmsg_close_table(&mBuf, modeTable);

        blobmsg_add_string(&mBuf, "DeviceType", neighborInfo.mFullThreadDevice ? "ftd" : "mtd");

        blobmsg_add_string(&mBuf, "Role", neighborInfo.mIsChild ? "child" : "router");

        blobmsg_close_table(&mBuf, neighborTable);
        neighborCount++;
    }
    blobmsg_close_array(&mBuf, neighborArray);
    blobmsg_add_u32(&mBuf, "NeighborCount", neighborCount);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: nat64status ========================
// ubus call otbr-agent nat64status
// Returns: NAT64 status information including translator state, prefix manager state,
//          CIDR, protocol counters, error counters, and address mappings

int UbusAgentExt::HandleNat64status(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
                                    struct ubus_request_data *aRequest,
                                    const char               *aMethod,
                                    struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().Nat64statusDetail(aContext, aRequest);
}

int UbusAgentExt::Nat64statusDetail(struct ubus_context      *aContext,
                                    struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // Helper lambda to convert NAT64 state to string
    auto nat64StateToStr = [](otNat64State aState) -> const char * {
        switch (aState)
        {
        case OT_NAT64_STATE_DISABLED:
            return "disabled";
        case OT_NAT64_STATE_NOT_RUNNING:
            return "not_running";
        case OT_NAT64_STATE_IDLE:
            return "idle";
        case OT_NAT64_STATE_ACTIVE:
            return "active";
        default:
            return "unknown";
        }
    };

#if OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE
    // --- Translator state ---
    {
        otNat64State translatorState = otNat64GetTranslatorState(instance);
        blobmsg_add_string(&mBuf, "Translator", nat64StateToStr(translatorState));
    }

    // --- IPv4 CIDR ---
    {
        otIp4Cidr cidr;
        if (otNat64GetCidr(instance, &cidr) == OT_ERROR_NONE)
        {
            char cidrStr[OT_IP4_CIDR_STRING_SIZE];
            otIp4CidrToString(&cidr, cidrStr, sizeof(cidrStr));
            blobmsg_add_string(&mBuf, "Cidr", cidrStr);
        }
        else
        {
            blobmsg_add_string(&mBuf, "Cidr", "not_configured");
        }
    }

    // --- Protocol counters ---
    {
        otNat64ProtocolCounters counters;
        otNat64GetCounters(instance, &counters);

        void *cntTable = blobmsg_open_table(&mBuf, "Counters");

        // Total
        {
            void *t = blobmsg_open_table(&mBuf, "Total");
            blobmsg_add_u64(&mBuf, "4to6_packets", counters.mTotal.m4To6Packets);
            blobmsg_add_u64(&mBuf, "4to6_bytes",   counters.mTotal.m4To6Bytes);
            blobmsg_add_u64(&mBuf, "6to4_packets", counters.mTotal.m6To4Packets);
            blobmsg_add_u64(&mBuf, "6to4_bytes",   counters.mTotal.m6To4Bytes);
            blobmsg_close_table(&mBuf, t);
        }
        // ICMP
        {
            void *t = blobmsg_open_table(&mBuf, "Icmp");
            blobmsg_add_u64(&mBuf, "4to6_packets", counters.mIcmp.m4To6Packets);
            blobmsg_add_u64(&mBuf, "4to6_bytes",   counters.mIcmp.m4To6Bytes);
            blobmsg_add_u64(&mBuf, "6to4_packets", counters.mIcmp.m6To4Packets);
            blobmsg_add_u64(&mBuf, "6to4_bytes",   counters.mIcmp.m6To4Bytes);
            blobmsg_close_table(&mBuf, t);
        }
        // UDP
        {
            void *t = blobmsg_open_table(&mBuf, "Udp");
            blobmsg_add_u64(&mBuf, "4to6_packets", counters.mUdp.m4To6Packets);
            blobmsg_add_u64(&mBuf, "4to6_bytes",   counters.mUdp.m4To6Bytes);
            blobmsg_add_u64(&mBuf, "6to4_packets", counters.mUdp.m6To4Packets);
            blobmsg_add_u64(&mBuf, "6to4_bytes",   counters.mUdp.m6To4Bytes);
            blobmsg_close_table(&mBuf, t);
        }
        // TCP
        {
            void *t = blobmsg_open_table(&mBuf, "Tcp");
            blobmsg_add_u64(&mBuf, "4to6_packets", counters.mTcp.m4To6Packets);
            blobmsg_add_u64(&mBuf, "4to6_bytes",   counters.mTcp.m4To6Bytes);
            blobmsg_add_u64(&mBuf, "6to4_packets", counters.mTcp.m6To4Packets);
            blobmsg_add_u64(&mBuf, "6to4_bytes",   counters.mTcp.m6To4Bytes);
            blobmsg_close_table(&mBuf, t);
        }

        blobmsg_close_table(&mBuf, cntTable);
    }

    // --- Error counters ---
    {
        otNat64ErrorCounters errCounters;
        otNat64GetErrorCounters(instance, &errCounters);

        void *errTable = blobmsg_open_table(&mBuf, "ErrorCounters");

        {
            void *t = blobmsg_open_table(&mBuf, "4to6");
            blobmsg_add_u64(&mBuf, "Unknown",          errCounters.mCount4To6[OT_NAT64_DROP_REASON_UNKNOWN]);
            blobmsg_add_u64(&mBuf, "IllegalPacket",   errCounters.mCount4To6[OT_NAT64_DROP_REASON_ILLEGAL_PACKET]);
            blobmsg_add_u64(&mBuf, "UnsupportedProto", errCounters.mCount4To6[OT_NAT64_DROP_REASON_UNSUPPORTED_PROTO]);
            blobmsg_add_u64(&mBuf, "NoMapping",       errCounters.mCount4To6[OT_NAT64_DROP_REASON_NO_MAPPING]);
            blobmsg_close_table(&mBuf, t);
        }
        {
            void *t = blobmsg_open_table(&mBuf, "6to4");
            blobmsg_add_u64(&mBuf, "Unknown",          errCounters.mCount6To4[OT_NAT64_DROP_REASON_UNKNOWN]);
            blobmsg_add_u64(&mBuf, "IllegalPacket",   errCounters.mCount6To4[OT_NAT64_DROP_REASON_ILLEGAL_PACKET]);
            blobmsg_add_u64(&mBuf, "UnsupportedProto", errCounters.mCount6To4[OT_NAT64_DROP_REASON_UNSUPPORTED_PROTO]);
            blobmsg_add_u64(&mBuf, "NoMapping",       errCounters.mCount6To4[OT_NAT64_DROP_REASON_NO_MAPPING]);
            blobmsg_close_table(&mBuf, t);
        }

        blobmsg_close_table(&mBuf, errTable);
    }

    // --- Active address mappings ---
    {
        void *mapArray = blobmsg_open_array(&mBuf, "Mappings");

        otNat64AddressMappingIterator mapIterator;
        otNat64InitAddressMappingIterator(instance, &mapIterator);

        otNat64AddressMapping mapping;
        while (otNat64GetNextAddressMapping(instance, &mapIterator, &mapping) == OT_ERROR_NONE)
        {
            void *mapItem = blobmsg_open_table(&mBuf, nullptr);

            blobmsg_add_u64(&mBuf, "Id", mapping.mId);

            char ip4Str[OT_IP4_ADDRESS_STRING_SIZE];
            otIp4AddressToString(&mapping.mIp4, ip4Str, sizeof(ip4Str));
            blobmsg_add_string(&mBuf, "Ipv4", ip4Str);

            char ip6Str[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6AddressToString(&mapping.mIp6, ip6Str, sizeof(ip6Str));
            blobmsg_add_string(&mBuf, "Ipv6", ip6Str);

            blobmsg_add_u32(&mBuf, "RemainingTimeMs", mapping.mRemainingTimeMs);

            // Per-mapping counters (total only)
            blobmsg_add_u64(&mBuf, "4to6Packets", mapping.mCounters.mTotal.m4To6Packets);
            blobmsg_add_u64(&mBuf, "4to6Bytes",   mapping.mCounters.mTotal.m4To6Bytes);
            blobmsg_add_u64(&mBuf, "6to4Packets", mapping.mCounters.mTotal.m6To4Packets);
            blobmsg_add_u64(&mBuf, "6to4Bytes",   mapping.mCounters.mTotal.m6To4Bytes);

            blobmsg_close_table(&mBuf, mapItem);
        }

        blobmsg_close_array(&mBuf, mapArray);
    }
#else
    blobmsg_add_string(&mBuf, "Translator", "not_compiled");
#endif // OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE

#if OPENTHREAD_CONFIG_NAT64_BORDER_ROUTING_ENABLE
    // --- Prefix manager state ---
    {
        otNat64State pmState = otNat64GetPrefixManagerState(instance);
        blobmsg_add_string(&mBuf, "PrefixManager", nat64StateToStr(pmState));
    }

    // --- NAT64 prefix from Border Routing ---
    {
        otIp6Prefix nat64Prefix;
        if (otBorderRoutingGetNat64Prefix(instance, &nat64Prefix) == OT_ERROR_NONE)
        {
            char prefixStr[OT_IP6_PREFIX_STRING_SIZE];
            otIp6PrefixToString(&nat64Prefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Nat64Prefix", prefixStr);
        }
    }
#endif // OPENTHREAD_CONFIG_NAT64_BORDER_ROUTING_ENABLE

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: getprefix ==========================
// ubus call otbr-agent getprefix
// Returns: On-mesh prefix list

int UbusAgentExt::HandleGetprefix(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
                                  struct ubus_request_data *aRequest,
                                  const char               *aMethod,
                                  struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().GetprefixDetail(aContext, aRequest);
}

int UbusAgentExt::HandleGetOmrPrefix(struct ubus_context      *aContext,
                                     struct ubus_object       *aObj,
                                     struct ubus_request_data *aRequest,
                                     const char               *aMethod,
                                     struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().GetOmrPrefixDetail(aContext, aRequest);
}

int UbusAgentExt::GetprefixDetail(struct ubus_context      *aContext,
                                  struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otDeviceRole role = otThreadGetDeviceRole(instance);

    if (!IsThreadAttachedRole(role))
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *prefixArray = blobmsg_open_array(&mBuf, "prefixes");
        blobmsg_close_array(&mBuf, prefixArray);
        mNcpThreadMutex->unlock();
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
    otBorderRouterConfig config;

    void *prefixArray = blobmsg_open_array(&mBuf, "prefixes");
    while (otNetDataGetNextOnMeshPrefix(instance, &iterator, &config) == OT_ERROR_NONE)
    {
        char prefixStr[OT_IP6_ADDRESS_STRING_SIZE];
        otIp6PrefixToString(&config.mPrefix, prefixStr, sizeof(prefixStr));
        blobmsg_add_string(&mBuf, nullptr, prefixStr);
    }
    blobmsg_close_array(&mBuf, prefixArray);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

int UbusAgentExt::GetOmrPrefixDetail(struct ubus_context      *aContext,
                                     struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otDeviceRole role = otThreadGetDeviceRole(instance);

    if (!IsThreadAttachedRole(role))
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        mNcpThreadMutex->unlock();
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

#if OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE
    {
        char        prefixStr[OT_IP6_PREFIX_STRING_SIZE] = {0};
        otIp6Prefix localPrefix;

        if (otBorderRoutingGetOmrPrefix(instance, &localPrefix) == OT_ERROR_NONE)
        {
            otIp6PrefixToString(&localPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Local", prefixStr);
        }
    }

    {
        char              prefixStr[OT_IP6_PREFIX_STRING_SIZE] = {0};
        otIp6Prefix       favoredPrefix;
        otRoutePreference preference;

        if (otBorderRoutingGetFavoredOmrPrefix(instance, &favoredPrefix, &preference) == OT_ERROR_NONE)
        {
            otIp6PrefixToString(&favoredPrefix, prefixStr, sizeof(prefixStr));
            blobmsg_add_string(&mBuf, "Favored", prefixStr);
        }
    }
#else
    blobmsg_add_string(&mBuf, "Error", "border_routing_disabled");
#endif

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: routerlist =========================
// ubus call otbr-agent routerlist
// Returns: Router list in the Thread network

int UbusAgentExt::HandleRouterlist(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().RouterlistDetail(aContext, aRequest);
}

int UbusAgentExt::RouterlistDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otRouterInfo routerInfo;
    uint8_t maxRouterId = otThreadGetMaxRouterId(instance);

    void *routerArray = blobmsg_open_array(&mBuf, "routers");
    for (uint8_t i = 0; i <= maxRouterId; i++)
    {
        if (otThreadGetRouterInfo(instance, i, &routerInfo) == OT_ERROR_NONE)
        {
            void *routerTable = blobmsg_open_table(&mBuf, nullptr);

            char extAddrStr[32] = {0};
            OutputBytes(routerInfo.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
            // Handle case where ext address is all zeros (use device's own address)
            if (strncmp(extAddrStr, "0000000000000000", 16) == 0)
            {
                const otExtAddress *ownAddr = otLinkGetExtendedAddress(instance);
                OutputBytes(ownAddr->m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
            }

            blobmsg_add_u32(&mBuf, "Rloc16", routerInfo.mRloc16);
            blobmsg_add_string(&mBuf, "ExtAddr", extAddrStr);

            blobmsg_close_table(&mBuf, routerTable);
        }
    }
    blobmsg_close_array(&mBuf, routerArray);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// ================ Handler: setnetworkconfig ===================
// ubus call otbr-agent setnetworkconfig '{"networkname":"OpenThread","panid":"0x1234",...}'
// Sets the Thread network configuration via Active Dataset

int UbusAgentExt::HandleSetnetworkconfig(struct ubus_context      *aContext,
                                         struct ubus_object       *aObj,
                                         struct ubus_request_data *aRequest,
                                         const char               *aMethod,
                                         struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SetnetworkconfigDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetnetworkconfigDetail(struct ubus_context      *aContext,
                                         struct ubus_request_data *aRequest,
                                         struct blob_attr         *aMsg)
{
    struct blob_attr *tb[MGMTSET_MAX];
    otOperationalDatasetTlvs datasetTlvs;
    otOperationalDataset dataset;
    otError error = OT_ERROR_NONE;

    blob_buf_init(&mBuf, 0);

    if (aMsg == nullptr)
    {
        blobmsg_add_string(&mBuf, "Error", "missing_parameters");
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_INVALID_ARGS);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    memset(&dataset, 0, sizeof(dataset));
    memset(&datasetTlvs, 0, sizeof(datasetTlvs));

    // Get current active dataset
    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    otDatasetGetActive(instance, &dataset);
    otDatasetGetActiveTlvs(instance, &datasetTlvs);

    // Reuse existing mgmtsetPolicy for parameter parsing
    blobmsg_parse(mgmtsetPolicy, MGMTSET_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (tb[MGMTSET_NETWORKKEY] != nullptr)
    {
        dataset.mComponents.mIsNetworkKeyPresent = true;
        int len = HexStringToBytes(blobmsg_get_string(tb[MGMTSET_NETWORKKEY]), dataset.mNetworkKey.m8, sizeof(dataset.mNetworkKey.m8));
        if (len != OT_NETWORK_KEY_SIZE)
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

    if (tb[MGMTSET_NETWORKNAME] != nullptr)
    {
        const char *name = blobmsg_get_string(tb[MGMTSET_NETWORKNAME]);
        size_t len = strlen(name);
        if (len > OT_NETWORK_NAME_MAX_SIZE)
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }
        dataset.mComponents.mIsNetworkNamePresent = true;
        memset(&dataset.mNetworkName, 0, sizeof(dataset.mNetworkName));
        memcpy(dataset.mNetworkName.m8, name, len);
    }

    if (tb[MGMTSET_EXTPANID] != nullptr)
    {
        dataset.mComponents.mIsExtendedPanIdPresent = true;
        int len = HexStringToBytes(blobmsg_get_string(tb[MGMTSET_EXTPANID]), dataset.mExtendedPanId.m8, sizeof(dataset.mExtendedPanId.m8));
        if (len != OT_EXT_PAN_ID_SIZE)
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

    if (tb[MGMTSET_PANID] != nullptr)
    {
        const char *panidStr = blobmsg_get_string(tb[MGMTSET_PANID]);
        char *endptr;
        long val = strtol(panidStr, &endptr, 0);
        if (val < 0 || val > 65535)
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }
        dataset.mComponents.mIsPanIdPresent = true;
        dataset.mPanId = (otPanId)val;
    }

    if (tb[MGMTSET_CHANNEL] != nullptr)
    {
        const char *channelStr = blobmsg_get_string(tb[MGMTSET_CHANNEL]);
        char *endptr;
        long val = strtol(channelStr, &endptr, 0);
        if (val < 11 || val > 26)
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }
        dataset.mComponents.mIsChannelPresent = true;
        dataset.mChannel = (uint16_t)val;
    }

    if (tb[MGMTSET_PSKC] != nullptr)
    {
        dataset.mComponents.mIsPskcPresent = true;
        int len = HexStringToBytes(blobmsg_get_string(tb[MGMTSET_PSKC]), dataset.mPskc.m8, sizeof(dataset.mPskc.m8));
        if (len != OT_PSKC_MAX_SIZE)
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

    if (tb[MGMTSET_TIMESTAMP] != nullptr)
    {
        dataset.mActiveTimestamp.mSeconds = blobmsg_get_u32(tb[MGMTSET_TIMESTAMP]);
    }
    else
    {
        dataset.mActiveTimestamp.mSeconds++;
    }

    // Update dataset TLVs and set as active
    error = otDatasetUpdateTlvs(&dataset, &datasetTlvs);
    if (error == OT_ERROR_NONE)
    {
        error = otDatasetSetActiveTlvs(instance, &datasetTlvs);
    }

exit:
    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Status", "success");
    }
    else
    {
        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));
    }
    blobmsg_add_u32(&mBuf, "ErrorCode", error);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}
// Single integrated call that chains:
//   Phase 1: otMeshDiagDiscoverTopology (all routers, links, optionally ip6 addrs & children)
//   Phase 2: otMeshDiagQueryChildTable for each discovered router
//   Phase 3: otMeshDiagQueryChildrenIp6Addrs for each discovered router
//   Phase 4: otMeshDiagQueryRouterNeighborTable for each discovered router
//
// All options default to true. Set any to false to skip that phase.
// The ubus request is deferred and completed when all phases finish.

int UbusAgentExt::HandleMeshDiag(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().MeshDiagDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::MeshDiagDetail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest,
                                 struct blob_attr         *aMsg)
{
    struct blob_attr *tb[MESHDIAG_MAX];
    memset(tb, 0, sizeof(tb));

    blob_buf_init(&mBuf, 0);

    if (aMsg != nullptr)
    {
        blobmsg_parse(meshDiagPolicy, MESHDIAG_MAX, tb, blob_data(aMsg), blob_len(aMsg));
    }

    mNcpThreadMutex->lock();
    otDeviceRole role = otThreadGetDeviceRole(mController->GetInstance());
    mNcpThreadMutex->unlock();

    if (role != OT_DEVICE_ROLE_CHILD && role != OT_DEVICE_ROLE_ROUTER && role != OT_DEVICE_ROLE_LEADER)
    {
        blobmsg_add_string(&mBuf, "Status", "thread_not_ready");
        blobmsg_add_string(&mBuf, "Role", RoleToString(role));
        blobmsg_add_u32(&mBuf, "ErrorCode", OT_ERROR_NONE);
        void *routerArray = blobmsg_open_array(&mBuf, "Routers");
        blobmsg_close_array(&mBuf, routerArray);
        blobmsg_add_u32(&mBuf, "RouterCount", 0);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    // Check if a meshdiag operation is already in progress
    {
        std::lock_guard<std::mutex> lock(mMeshDiagMutex);
        if (mMeshDiagPhase != kMeshDiagIdle && !mMeshDiagDone)
        {
            blobmsg_add_string(&mBuf, "Error", "busy");
            blobmsg_add_string(&mBuf, "Detail", "a meshdiag operation is already in progress");
            ubus_send_reply(aContext, aRequest, mBuf.head);
            return 0;
        }
    }

    // Parse options (all default to true for comprehensive scan)
    bool wantIp6Addrs   = (tb[MESHDIAG_IP6_ADDRS] != nullptr) ? blobmsg_get_bool(tb[MESHDIAG_IP6_ADDRS]) : true;
    bool wantChildren   = (tb[MESHDIAG_CHILDREN] != nullptr) ? blobmsg_get_bool(tb[MESHDIAG_CHILDREN]) : true;
    bool wantChildTable = (tb[MESHDIAG_CHILDTABLE] != nullptr) ? blobmsg_get_bool(tb[MESHDIAG_CHILDTABLE]) : true;
    bool wantChildIp6   = (tb[MESHDIAG_CHILDIP6] != nullptr) ? blobmsg_get_bool(tb[MESHDIAG_CHILDIP6]) : true;
    bool wantRouterNbr  = (tb[MESHDIAG_ROUTERNEIGHBORTABLE] != nullptr) ? blobmsg_get_bool(tb[MESHDIAG_ROUTERNEIGHBORTABLE]) : true;

    // Initialize state
    {
        std::lock_guard<std::mutex> lock(mMeshDiagMutex);
        mMeshDiagResults.clear();
        mMeshDiagPhase              = kMeshDiagTopology;
        mMeshDiagRouterIdx          = 0;
        mMeshDiagDone               = false;
        mMeshDiagFinalError         = OT_ERROR_NONE;
        mMeshDiagWantChildTable     = wantChildTable;
        mMeshDiagWantChildIp6       = wantChildIp6;
        mMeshDiagWantRouterNeighbor = wantRouterNbr;
    }

    // Start topology discovery (Phase 1)
    otMeshDiagDiscoverConfig config;
    config.mDiscoverIp6Addresses = wantIp6Addrs;
    config.mDiscoverChildTable   = wantChildren;

    mNcpThreadMutex->lock();
    otError error = otMeshDiagDiscoverTopology(mController->GetInstance(), &config,
                                               &UbusAgentExt::HandleMeshDiagDiscoverDone, this);
    mNcpThreadMutex->unlock();

    if (error != OT_ERROR_NONE)
    {
        std::lock_guard<std::mutex> lock(mMeshDiagMutex);
        mMeshDiagPhase = kMeshDiagIdle;

        blobmsg_add_string(&mBuf, "Error", otThreadErrorToString(error));
        blobmsg_add_u32(&mBuf, "ErrorCode", error);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    // Defer the ubus request — reply sent when all phases complete
    ubus_defer_request(aContext, aRequest, &mMeshDiagDeferredReq);
    mMeshDiagUbusCtx = aContext;

    return 0;
}

// ---- Phase advancement state machine (called from OT thread) ----

void UbusAgentExt::AdvanceMeshDiagPhase(void)
{
    // Called from OT thread when current phase's query completes.
    // Determines the next query to start, or marks entire operation done.

    otInstance *instance = mController->GetInstance();

    while (true)
    {
        // Decide what to do next based on current phase
        switch (mMeshDiagPhase)
        {
        case kMeshDiagTopology:
            if (mMeshDiagWantChildTable && !mMeshDiagResults.empty())
            {
                mMeshDiagPhase     = kMeshDiagChildTable;
                mMeshDiagRouterIdx = 0;
            }
            else if (mMeshDiagWantChildIp6 && !mMeshDiagResults.empty())
            {
                mMeshDiagPhase     = kMeshDiagChildIp6;
                mMeshDiagRouterIdx = 0;
            }
            else if (mMeshDiagWantRouterNeighbor && !mMeshDiagResults.empty())
            {
                mMeshDiagPhase     = kMeshDiagRouterNeighbor;
                mMeshDiagRouterIdx = 0;
            }
            else
            {
                goto done;
            }
            break;

        case kMeshDiagChildTable:
            mMeshDiagRouterIdx++;
            if (mMeshDiagRouterIdx >= mMeshDiagResults.size())
            {
                if (mMeshDiagWantChildIp6 && !mMeshDiagResults.empty())
                {
                    mMeshDiagPhase     = kMeshDiagChildIp6;
                    mMeshDiagRouterIdx = 0;
                }
                else if (mMeshDiagWantRouterNeighbor && !mMeshDiagResults.empty())
                {
                    mMeshDiagPhase     = kMeshDiagRouterNeighbor;
                    mMeshDiagRouterIdx = 0;
                }
                else
                {
                    goto done;
                }
            }
            break;

        case kMeshDiagChildIp6:
            mMeshDiagRouterIdx++;
            if (mMeshDiagRouterIdx >= mMeshDiagResults.size())
            {
                if (mMeshDiagWantRouterNeighbor && !mMeshDiagResults.empty())
                {
                    mMeshDiagPhase     = kMeshDiagRouterNeighbor;
                    mMeshDiagRouterIdx = 0;
                }
                else
                {
                    goto done;
                }
            }
            break;

        case kMeshDiagRouterNeighbor:
            mMeshDiagRouterIdx++;
            if (mMeshDiagRouterIdx >= mMeshDiagResults.size())
            {
                goto done;
            }
            break;

        default:
            goto done;
        }

        // Start the query for the current phase/router
        uint16_t rloc16 = mMeshDiagResults[mMeshDiagRouterIdx].mRloc16;
        otError  err    = OT_ERROR_NONE;

        switch (mMeshDiagPhase)
        {
        case kMeshDiagChildTable:
            err = otMeshDiagQueryChildTable(instance, rloc16,
                                            &UbusAgentExt::HandleMeshDiagChildTableResult, this);
            break;
        case kMeshDiagChildIp6:
            err = otMeshDiagQueryChildrenIp6Addrs(instance, rloc16,
                                                   &UbusAgentExt::HandleMeshDiagChildIp6Addrs, this);
            break;
        case kMeshDiagRouterNeighbor:
            err = otMeshDiagQueryRouterNeighborTable(instance, rloc16,
                                                      &UbusAgentExt::HandleMeshDiagRouterNeighborTableResult, this);
            break;
        default:
            goto done;
        }

        if (err == OT_ERROR_NONE)
        {
            return;  // Query started, wait for callback
        }

        // Query failed for this router (e.g., offline), skip to next
        otbrLogWarning("meshdiag: phase %d skipped router 0x%04x: %s",
                       mMeshDiagPhase, rloc16, otThreadErrorToString(err));
        // Loop continues to try next router/phase
    }

done:
    {
        std::lock_guard<std::mutex> lock(mMeshDiagMutex);
        mMeshDiagPhase = kMeshDiagComplete;
        mMeshDiagDone  = true;
    }
}

// ---- MeshDiag Topology Callback (Phase 1) ----

void UbusAgentExt::HandleMeshDiagDiscoverDone(otError aError, otMeshDiagRouterInfo *aRouterInfo, void *aContext)
{
    reinterpret_cast<UbusAgentExt *>(aContext)->HandleMeshDiagDiscoverDone(aError, aRouterInfo);
}

void UbusAgentExt::HandleMeshDiagDiscoverDone(otError aError, otMeshDiagRouterInfo *aRouterInfo)
{
    if (aRouterInfo != nullptr)
    {
        MeshDiagRouterResult result;
        result.mRouterId           = aRouterInfo->mRouterId;
        result.mRloc16             = aRouterInfo->mRloc16;
        result.mExtAddress         = aRouterInfo->mExtAddress;
        result.mVersion            = aRouterInfo->mVersion;
        result.mIsThisDevice       = aRouterInfo->mIsThisDevice;
        result.mIsLeader           = aRouterInfo->mIsLeader;
        result.mIsBorderRouter     = aRouterInfo->mIsBorderRouter;
        memcpy(result.mLinkQualities, aRouterInfo->mLinkQualities, sizeof(result.mLinkQualities));

        if (aRouterInfo->mIp6AddrIterator != nullptr)
        {
            otIp6Address ip6Addr;
            while (otMeshDiagGetNextIp6Address(aRouterInfo->mIp6AddrIterator, &ip6Addr) == OT_ERROR_NONE)
            {
                result.mIp6Addresses.push_back(ip6Addr);
            }
        }

        if (aRouterInfo->mChildIterator != nullptr)
        {
            otMeshDiagChildInfo childInfo;
            while (otMeshDiagGetNextChildInfo(aRouterInfo->mChildIterator, &childInfo) == OT_ERROR_NONE)
            {
                result.mChildren.push_back(childInfo);
            }
        }

        mMeshDiagResults.push_back(std::move(result));
    }

    if (aError != OT_ERROR_PENDING)
    {
        if (aError == OT_ERROR_RESPONSE_TIMEOUT)
        {
            mMeshDiagFinalError = aError;
        }
        AdvanceMeshDiagPhase();
    }
}

// ---- MeshDiag ChildTable Callback (Phase 2) ----

void UbusAgentExt::HandleMeshDiagChildTableResult(otError aError, const otMeshDiagChildEntry *aChildEntry, void *aContext)
{
    reinterpret_cast<UbusAgentExt *>(aContext)->HandleMeshDiagChildTableResult(aError, aChildEntry);
}

void UbusAgentExt::HandleMeshDiagChildTableResult(otError aError, const otMeshDiagChildEntry *aChildEntry)
{
    if (aChildEntry != nullptr && mMeshDiagRouterIdx < mMeshDiagResults.size())
    {
        mMeshDiagResults[mMeshDiagRouterIdx].mChildTable.push_back(*aChildEntry);
    }

    if (aError != OT_ERROR_PENDING)
    {
        AdvanceMeshDiagPhase();
    }
}

// ---- MeshDiag ChildIp6Addrs Callback (Phase 3) ----

void UbusAgentExt::HandleMeshDiagChildIp6Addrs(otError aError, uint16_t aChildRloc16,
                                                otMeshDiagIp6AddrIterator *aIp6AddrIterator, void *aContext)
{
    reinterpret_cast<UbusAgentExt *>(aContext)->HandleMeshDiagChildIp6Addrs(aError, aChildRloc16, aIp6AddrIterator);
}

void UbusAgentExt::HandleMeshDiagChildIp6Addrs(otError aError, uint16_t aChildRloc16,
                                                otMeshDiagIp6AddrIterator *aIp6AddrIterator)
{
    if (aIp6AddrIterator != nullptr && (aError == OT_ERROR_NONE || aError == OT_ERROR_PENDING)
        && mMeshDiagRouterIdx < mMeshDiagResults.size())
    {
        MeshDiagChildIp6Result entry;
        entry.mChildRloc16 = aChildRloc16;

        otIp6Address ip6Addr;
        while (otMeshDiagGetNextIp6Address(aIp6AddrIterator, &ip6Addr) == OT_ERROR_NONE)
        {
            entry.mAddresses.push_back(ip6Addr);
        }

        mMeshDiagResults[mMeshDiagRouterIdx].mChildIp6.push_back(std::move(entry));
    }

    if (aError != OT_ERROR_PENDING)
    {
        AdvanceMeshDiagPhase();
    }
}

// ---- MeshDiag RouterNeighborTable Callback (Phase 4) ----

void UbusAgentExt::HandleMeshDiagRouterNeighborTableResult(otError aError,
                                                            const otMeshDiagRouterNeighborEntry *aNeighborEntry,
                                                            void *aContext)
{
    reinterpret_cast<UbusAgentExt *>(aContext)->HandleMeshDiagRouterNeighborTableResult(aError, aNeighborEntry);
}

void UbusAgentExt::HandleMeshDiagRouterNeighborTableResult(otError aError,
                                                            const otMeshDiagRouterNeighborEntry *aNeighborEntry)
{
    if (aNeighborEntry != nullptr && mMeshDiagRouterIdx < mMeshDiagResults.size())
    {
        mMeshDiagResults[mMeshDiagRouterIdx].mRouterNeighbors.push_back(*aNeighborEntry);
    }

    if (aError != OT_ERROR_PENDING)
    {
        AdvanceMeshDiagPhase();
    }
}

// ---- Complete deferred meshdiag request (called from ubus thread via drain timer) ----

void UbusAgentExt::CompleteMeshDiagDeferred(void)
{
    std::lock_guard<std::mutex> lock(mMeshDiagMutex);

    if (mMeshDiagPhase == kMeshDiagIdle || !mMeshDiagDone)
    {
        return;
    }

    if (mMeshDiagUbusCtx == nullptr)
    {
        mMeshDiagPhase = kMeshDiagIdle;
        return;
    }

    struct blob_buf b;
    memset(&b, 0, sizeof(b));
    blob_buf_init(&b, 0);

    char extAddrStr[OT_EXT_ADDRESS_SIZE * 2 + 1] = "";
    char addrStr[OT_IP6_ADDRESS_STRING_SIZE];

    if (mMeshDiagFinalError == OT_ERROR_RESPONSE_TIMEOUT)
    {
        blobmsg_add_string(&b, "warning", "response_timeout");
    }

    void *routerArray = blobmsg_open_array(&b, "Routers");

    for (const auto &router : mMeshDiagResults)
    {
        void *routerEntry = blobmsg_open_table(&b, nullptr);

        // -- Basic topology info --
        blobmsg_add_u32(&b, "RouterId", router.mRouterId);
        AddRloc16ToBlob(&b, "Rloc16", router.mRloc16);
        OutputBytesToUpper(router.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
        blobmsg_add_string(&b, "ExtAddress", extAddrStr);

        if (router.mVersion != OT_MESH_DIAG_VERSION_UNKNOWN)
        {
            blobmsg_add_u32(&b, "Version", router.mVersion);
        }

        AddBlobMsgBool(&b, "IsThisDevice", router.mIsThisDevice);
        AddBlobMsgBool(&b, "IsLeader", router.mIsLeader);
        AddBlobMsgBool(&b, "IsBorderRouter", router.mIsBorderRouter);
        AddBlobMsgBool(&b, "IsOnline", true);

        // -- Mode (device mode flags) --
        // Note: For router entries, we need to determine mode from leader flag and border router flag
        // Since meshdiag doesn't provide full mode info for routers, use defaults for FTD routers
        void *modeTable = blobmsg_open_table(&b, "Mode");
        blobmsg_add_u32(&b, "RxOnWhenIdle", 1); // Routers are always RxOnWhenIdle
        blobmsg_add_u32(&b, "DeviceType", 1);   // Routers are FTDs
        blobmsg_add_u32(&b, "NetworkData", 1);  // Routers typically have full network data
        blobmsg_close_table(&b, modeTable);

        // -- LeaderData (find the leader router from all results) --
        // Always create LeaderData object, even if no leader is found
        void *leaderDataTbl = blobmsg_open_table(&b, "LeaderData");
        int leaderRouterId = -1; // Default value if no leader found
        for (const auto &r : mMeshDiagResults)
        {
            if (r.mIsLeader)
            {
                leaderRouterId = r.mRouterId;
                break;
            }
        }
        blobmsg_add_u32(&b, "PartitionId", 0); // Not available in meshdiag, set to 0
        blobmsg_add_u32(&b, "Weighting", 0);
        blobmsg_add_u32(&b, "DataVersion", 0);
        blobmsg_add_u32(&b, "StableDataVersion", 0);
        blobmsg_add_u32(&b, "LeaderRouterId", leaderRouterId >= 0 ? leaderRouterId : 0);
        blobmsg_close_table(&b, leaderDataTbl);

        // -- Links to other routers (link_quality: 3=best, 2=good, 1=weak) --
        {
            void *linkArray = blobmsg_open_array(&b, "Links");

            for (uint8_t id = 0; id <= OT_NETWORK_MAX_ROUTER_ID; id++)
            {
                uint8_t lq = router.mLinkQualities[id];
                if (lq == 0)
                {
                    continue;
                }

                void *linkEntry = blobmsg_open_table(&b, nullptr);
                blobmsg_add_u32(&b, "RouterId", id);
                blobmsg_add_u32(&b, "LinkQuality", lq);

                // Cross-reference topology results for rloc16 and ext_addr
                for (const auto &r : mMeshDiagResults)
                {
                    if (r.mRouterId == id)
                    {
                        AddRloc16ToBlob(&b, "Rloc16", r.mRloc16);
                        OutputBytesToUpper(r.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
                        blobmsg_add_string(&b, "ExtAddress", extAddrStr);
                        blobmsg_add_string(&b, "Name", "");
                        break;
                    }
                }

                blobmsg_close_table(&b, linkEntry);
            }

            blobmsg_close_array(&b, linkArray);
        }

        // -- IPv6 addresses (from topology discovery) --
        if (!router.mIp6Addresses.empty())
        {
            void *addrArray = blobmsg_open_array(&b, "IP6AddressList");
            for (const auto &addr : router.mIp6Addresses)
            {
                otIp6AddressToString(&addr, addrStr, sizeof(addrStr));
                blobmsg_add_string(&b, nullptr, addrStr);
            }
            blobmsg_close_array(&b, addrArray);
        }

        // -- Children (merged from topology discovery + childtable + childip6) --
        // Build lookup maps for childtable and childip6 by RLOC16
        std::map<uint16_t, const otMeshDiagChildEntry *> childTableMap;
        for (const auto &ct : router.mChildTable)
        {
            childTableMap[ct.mRloc16] = &ct;
        }

        std::map<uint16_t, const MeshDiagChildIp6Result *> childIp6Map;
        for (const auto &cip : router.mChildIp6)
        {
            childIp6Map[cip.mChildRloc16] = &cip;
        }

        // Collect all unique child RLOC16s
        std::set<uint16_t> allChildRlocs;
        for (const auto &c : router.mChildren)
            allChildRlocs.insert(c.mRloc16);
        for (const auto &ct : router.mChildTable)
            allChildRlocs.insert(ct.mRloc16);
        for (const auto &cip : router.mChildIp6)
            allChildRlocs.insert(cip.mChildRloc16);

        // Always create ChildTable array (empty if no children)
        void *childArray = blobmsg_open_array(&b, "ChildTable");

        for (uint16_t childRloc : allChildRlocs)
        {
            void *childEntry = blobmsg_open_table(&b, nullptr);

            AddRloc16ToBlob(&b, "Rloc16", childRloc);
            blobmsg_add_u32(&b, "ChildId", childRloc & 0x03FF);

            // Look up in childtable (detailed info)
            auto ctIt = childTableMap.find(childRloc);
            if (ctIt != childTableMap.end())
            {
                const otMeshDiagChildEntry *ct = ctIt->second;
                OutputBytesToUpper(ct->mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
                blobmsg_add_string(&b, "ExtAddress", extAddrStr);
                blobmsg_add_string(&b, "Name", "");
                blobmsg_add_u32(&b, "Version", ct->mVersion);
                blobmsg_add_u32(&b, "Timeout", ct->mTimeout);
                blobmsg_add_u32(&b, "Age", ct->mAge);
                blobmsg_add_u32(&b, "ConnectionTimeOrig", ct->mConnectionTime);
                {
                    std::string connectionTimeStd = SecondsToHmsString(ct->mConnectionTime);
                    blobmsg_add_string(&b, "ConnectionTime", connectionTimeStd.c_str());
                }
                blobmsg_add_u32(&b, "SupervisionInterval", ct->mSupervisionInterval);
                blobmsg_add_u32(&b, "LinkMargin", ct->mLinkMargin);
                blobmsg_add_u32(&b, "AvgRssi", (uint32_t)(int32_t)ct->mAverageRssi);
                blobmsg_add_u32(&b, "LastRssi", (uint32_t)(int32_t)ct->mLastRssi);

                // Mode object
                void *modeTable = blobmsg_open_table(&b, "Mode");
                blobmsg_add_u32(&b, "RxOnWhenIdle", ct->mRxOnWhenIdle);
                blobmsg_add_u32(&b, "DeviceType", ct->mDeviceTypeFtd);
                blobmsg_add_u32(&b, "NetworkData", ct->mFullNetData);
                blobmsg_close_table(&b, modeTable);

                blobmsg_add_u8(&b, "CslSynchronized", ct->mCslSynchronized);
                blobmsg_add_string(&b, "CslSync", ct->mCslSynchronized ? "yes" : "no");
                blobmsg_add_u32(&b, "QueuedMessageCount", ct->mQueuedMessageCount);
                if (ct->mSupportsErrRate)
                {
                    blobmsg_add_u32(&b, "FrameErrorRate", ct->mFrameErrorRate);
                    blobmsg_add_u32(&b, "MessageErrorRate", ct->mMessageErrorRate);
                }
                blobmsg_add_u32(&b, "CslPeriod", ct->mCslPeriod);
                blobmsg_add_u32(&b, "CslTimeout", ct->mCslTimeout);
                blobmsg_add_u32(&b, "CslChannel", ct->mCslChannel);

                // Look up IsThisDevice and IsBorderRouter from topology children
                for (const auto &tc : router.mChildren)
                {
                    if (tc.mRloc16 == childRloc)
                    {
                        AddBlobMsgBool(&b, "IsThisDevice", tc.mIsThisDevice);
                        AddBlobMsgBool(&b, "IsBorderRouter", tc.mIsBorderRouter);
                        AddBlobMsgBool(&b, "IsOnline", true);
                        break;
                    }
                }
            }

            // Look up link_quality and flags from topology children
            for (const auto &tc : router.mChildren)
            {
                if (tc.mRloc16 == childRloc)
                {
                    blobmsg_add_u32(&b, "LinkQuality", tc.mLinkQuality);
                    // Only add mode flags if childtable didn't provide them
                    if (ctIt == childTableMap.end())
                    {
                        void *modeTable = blobmsg_open_table(&b, "Mode");
                        blobmsg_add_u32(&b, "RxOnWhenIdle", tc.mMode.mRxOnWhenIdle);
                        blobmsg_add_u32(&b, "DeviceType", tc.mMode.mDeviceType);
                        blobmsg_add_u32(&b, "NetworkData", tc.mMode.mNetworkData);
                        blobmsg_close_table(&b, modeTable);
                    }
                    blobmsg_add_string(&b, "DeviceType", tc.mMode.mDeviceType ? "ftd" : "mtd");
                    AddBlobMsgBool(&b, "IsThisDevice", tc.mIsThisDevice);
                    AddBlobMsgBool(&b, "IsBorderRouter", tc.mIsBorderRouter);
                    AddBlobMsgBool(&b, "IsOnline", true);
                    break;
                }
            }

            // Look up IPv6 addresses from childip6
            auto cipIt = childIp6Map.find(childRloc);
            if (cipIt != childIp6Map.end() && !cipIt->second->mAddresses.empty())
            {
                void *ipArray = blobmsg_open_array(&b, "IP6AddressList");
                for (const auto &addr : cipIt->second->mAddresses)
                {
                    otIp6AddressToString(&addr, addrStr, sizeof(addrStr));
                    blobmsg_add_string(&b, nullptr, addrStr);
                }
                blobmsg_close_array(&b, ipArray);
            }

            blobmsg_close_table(&b, childEntry);
        }

        blobmsg_close_array(&b, childArray);

        // -- Router neighbor table (from routerneighbortable query) --
        if (!router.mRouterNeighbors.empty())
        {
            void *rnArray = blobmsg_open_array(&b, "NeighborRouterTable");
            for (const auto &neighbor : router.mRouterNeighbors)
            {
                void *rnEntry = blobmsg_open_table(&b, nullptr);
                AddRloc16ToBlob(&b, "Rloc16", neighbor.mRloc16);
                OutputBytesToUpper(neighbor.mExtAddress.m8, OT_EXT_ADDRESS_SIZE, extAddrStr);
                blobmsg_add_string(&b, "ExtAddress", extAddrStr);
                blobmsg_add_string(&b, "Name", "");
                blobmsg_add_u32(&b, "Version", neighbor.mVersion);
                blobmsg_add_u32(&b, "ConnectionTimeOrig", neighbor.mConnectionTime);
                {
                    std::string connectionTimeStd = SecondsToHmsString(neighbor.mConnectionTime);
                    blobmsg_add_string(&b, "ConnectionTime", connectionTimeStd.c_str());
                }
                blobmsg_add_u32(&b, "LinkMargin", neighbor.mLinkMargin);
                blobmsg_add_u32(&b, "AvgRssi", (uint32_t)(int32_t)neighbor.mAverageRssi);
                blobmsg_add_u32(&b, "LastRssi", (uint32_t)(int32_t)neighbor.mLastRssi);
                if (neighbor.mSupportsErrRate)
                {
                    blobmsg_add_u32(&b, "FrameErrorRate", neighbor.mFrameErrorRate);
                    blobmsg_add_u32(&b, "MessageErrorRate", neighbor.mMessageErrorRate);
                }

                // Look up IPv6 addresses and flags from topology discovery results
                for (const auto &r : mMeshDiagResults)
                {
                    if (r.mRloc16 == neighbor.mRloc16)
                    {
                        AddBlobMsgBool(&b, "IsThisDevice", r.mIsThisDevice);
                        AddBlobMsgBool(&b, "IsLeader", r.mIsLeader);
                        AddBlobMsgBool(&b, "IsBorderRouter", r.mIsBorderRouter);
                        AddBlobMsgBool(&b, "IsOnline", true);

                        if (!r.mIp6Addresses.empty())
                        {
                            void *ipArray = blobmsg_open_array(&b, "IP6AddressList");
                            for (const auto &addr : r.mIp6Addresses)
                            {
                                otIp6AddressToString(&addr, addrStr, sizeof(addrStr));
                                blobmsg_add_string(&b, nullptr, addrStr);
                            }
                            blobmsg_close_array(&b, ipArray);
                        }
                        break;
                    }
                }

                blobmsg_close_table(&b, rnEntry);
            }
            blobmsg_close_array(&b, rnArray);
        }

        blobmsg_close_table(&b, routerEntry);
    }

    blobmsg_close_array(&b, routerArray);
    blobmsg_add_u32(&b, "RouterNumber", (uint32_t)mMeshDiagResults.size());
    blobmsg_add_string(&b, "status",
                       (mMeshDiagFinalError == OT_ERROR_NONE) ? "ok" : otThreadErrorToString(mMeshDiagFinalError));

    ubus_send_reply(mMeshDiagUbusCtx, &mMeshDiagDeferredReq, b.head);
    ubus_complete_deferred_request(mMeshDiagUbusCtx, &mMeshDiagDeferredReq, 0);

    blob_buf_free(&b);

    // Reset state
    mMeshDiagPhase   = kMeshDiagIdle;
    mMeshDiagDone    = false;
    mMeshDiagUbusCtx = nullptr;
    mMeshDiagResults.clear();

    otbrLogInfo("otbr-agent: meshdiag completed");
}

// ==================== Additional Methods Implementation ====================

// =================== state (otbr-agent state) =========================
// ubus call otbr-agent state
// Returns the current Thread device role state (disabled/detached/child/router/leader)

int UbusAgentExt::HandleState(struct ubus_context      *aContext,
                              struct ubus_object       *aObj,
                              struct ubus_request_data *aRequest,
                              const char               *aMethod,
                              struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().StateDetail(aContext, aRequest);
}

int UbusAgentExt::StateDetail(struct ubus_context      *aContext,
                              struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();
    uint32_t    stateCode;

    const char *stateStr;
    switch (otThreadGetDeviceRole(instance))
    {
    case OT_DEVICE_ROLE_DISABLED:
        stateStr = "disabled";
        stateCode = 0;
        break;
    case OT_DEVICE_ROLE_DETACHED:
        stateStr = "detached";
        stateCode = 1;
        break;
    case OT_DEVICE_ROLE_CHILD:
        stateStr = "child";
        stateCode = 2;
        break;
    case OT_DEVICE_ROLE_ROUTER:
        stateStr = "router";
        stateCode = 3;
        break;
    case OT_DEVICE_ROLE_LEADER:
        stateStr = "leader";
        stateCode = 4;
        break;
    default:
        stateStr = "unknown";
        stateCode = static_cast<uint32_t>(otThreadGetDeviceRole(instance));
        break;
    }

    blobmsg_add_string(&mBuf, "State", stateStr);
    blobmsg_add_u32(&mBuf, "StateCode", stateCode);
    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== pskc (get PSKc) =========================
// ubus call otbr-agent pskc
// Returns the Thread PSKc value

int UbusAgentExt::HandlePskc(struct ubus_context      *aContext,
                             struct ubus_object       *aObj,
                             struct ubus_request_data *aRequest,
                             const char               *aMethod,
                             struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().PskcDetail(aContext, aRequest);
}

int UbusAgentExt::PskcDetail(struct ubus_context      *aContext,
                             struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    char   outputPskc[OT_PSKC_MAX_SIZE * 2 + 1] = "";
    otPskc pskc;

    otThreadGetPskc(instance, &pskc);

    // Convert bytes to hex string
    for (int i = 0; i < OT_PSKC_MAX_SIZE; i++)
    {
        char byte2char[5] = "";
        sprintf(byte2char, "%02x", pskc.m8[i]);
        strcat(outputPskc, byte2char);
    }

    blobmsg_add_string(&mBuf, "Pskc", outputPskc);
    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== threadstart =========================
// ubus call otbr-agent threadstart
// Starts the Thread network (enables IPv6 and Thread)

int UbusAgentExt::HandleThreadStart(struct ubus_context      *aContext,
                                    struct ubus_object       *aObj,
                                    struct ubus_request_data *aRequest,
                                    const char               *aMethod,
                                    struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().ThreadStartDetail(aContext, aRequest);
}

int UbusAgentExt::ThreadStartDetail(struct ubus_context      *aContext,
                                    struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    otError error = OT_ERROR_NONE;

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    error = otIp6SetEnabled(instance, true);
    if (error != OT_ERROR_NONE)
    {
        goto exit;
    }

    error = otThreadSetEnabled(instance, true);

exit:
    mNcpThreadMutex->unlock();

    blobmsg_add_u32(&mBuf, "Error", error);
    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== threadstop =========================
// ubus call otbr-agent threadstop
// Stops the Thread network (disables Thread and IPv6)

int UbusAgentExt::HandleThreadStop(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().ThreadStopDetail(aContext, aRequest);
}

int UbusAgentExt::ThreadStopDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    otError error = OT_ERROR_NONE;

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    error = otThreadSetEnabled(instance, false);
    if (error != OT_ERROR_NONE)
    {
        goto exit;
    }

    error = otIp6SetEnabled(instance, false);

exit:
    mNcpThreadMutex->unlock();

    blobmsg_add_u32(&mBuf, "Error", error);
    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== joinernum (get number of joiners) =========================
// ubus call otbr-agent joinernum
// Returns the number of active joiners in the commissioner

int UbusAgentExt::HandleJoinerNum(struct ubus_context      *aContext,
                                  struct ubus_object       *aObj,
                                  struct ubus_request_data *aRequest,
                                  const char               *aMethod,
                                  struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().JoinerNumDetail(aContext, aRequest);
}

int UbusAgentExt::JoinerNumDetail(struct ubus_context      *aContext,
                                  struct ubus_request_data *aRequest)
{
    char         addrStr[OT_EXT_ADDRESS_SIZE * 2 + 1];
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otJoinerInfo joinerInfo;
    uint16_t     iterator  = 0;
    uint32_t     joinerNum = 0;

    void *joinerArray = blobmsg_open_array(&mBuf, "JoinerList");

    while (otCommissionerGetNextJoinerInfo(instance, &iterator, &joinerInfo) == OT_ERROR_NONE)
    {
        void *joinerItem = blobmsg_open_table(&mBuf, nullptr);

        blobmsg_add_string(&mBuf, "Pskd", joinerInfo.mPskd.m8);

        switch (joinerInfo.mType)
        {
        case OT_JOINER_INFO_TYPE_ANY:
            blobmsg_add_string(&mBuf, "Type", "any");
            break;
        case OT_JOINER_INFO_TYPE_EUI64:
            blobmsg_add_string(&mBuf, "Type", "eui64");
            memset(addrStr, 0, sizeof(addrStr));
            OutputBytes(joinerInfo.mSharedId.mEui64.m8, sizeof(joinerInfo.mSharedId.mEui64.m8), addrStr);
            blobmsg_add_string(&mBuf, "Eui64", addrStr);
            break;
        case OT_JOINER_INFO_TYPE_DISCERNER:
            blobmsg_add_string(&mBuf, "Type", "discerner");
            blobmsg_add_u64(&mBuf, "DiscernerValue", joinerInfo.mSharedId.mDiscerner.mValue);
            blobmsg_add_u32(&mBuf, "DiscernerLength", joinerInfo.mSharedId.mDiscerner.mLength);
            break;
        }

        blobmsg_add_u32(&mBuf, "ExpirationMs", joinerInfo.mExpirationTime);

        blobmsg_close_table(&mBuf, joinerItem);
        joinerNum++;
    }

    blobmsg_close_array(&mBuf, joinerArray);

    blobmsg_add_u32(&mBuf, "JoinerNum", joinerNum);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== setleaderrole =========================
// ubus call otbr-agent setleaderrole
// Sets the device to leader role with LeaderData.Weighting + 1

int UbusAgentExt::HandleSetLeaderRole(struct ubus_context      *aContext,
                                      struct ubus_object       *aObj,
                                      struct ubus_request_data *aRequest,
                                      const char               *aMethod,
                                      struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().SetLeaderRoleDetail(aContext, aRequest);
}

int UbusAgentExt::SetLeaderRoleDetail(struct ubus_context      *aContext,
                                      struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    // Get current leader weight
    uint8_t currentWeight = otThreadGetLocalLeaderWeight(instance);
    uint8_t newWeight = currentWeight + 1;

    // Set the new leader weight
    otThreadSetLocalLeaderWeight(instance, newWeight);

    // Switch to leader role (similar to CLI: state leader)
    otError error = otThreadBecomeLeader(instance);

    blobmsg_add_u32(&mBuf, "PreviousWeight", currentWeight);
    blobmsg_add_u32(&mBuf, "NewWeight", newWeight);
    blobmsg_add_u32(&mBuf, "ErrorCode", error);

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_string(&mBuf, "Status", "success");
    }
    else
    {
        blobmsg_add_string(&mBuf, "Status", "failed");
    }

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== mgmtset (management set) =========================
// ubus call otbr-agent mgmtset '{"networkname":"xxx","networkkey":"xxx",...}'
// Sets the Thread Active Dataset

int UbusAgentExt::HandleMgmtset(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
                                struct ubus_request_data *aRequest,
                                const char               *aMethod,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().MgmtsetDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::MgmtsetDetail(struct ubus_context      *aContext,
                                struct ubus_request_data *aRequest,
                                struct blob_attr         *aMsg)
{
    blob_buf_init(&mBuf, 0);

    std::lock_guard<std::mutex> lock(*mNcpThreadMutex);
    otInstance                 *instance = mController->GetInstance();

    otError              error = OT_ERROR_NONE;
    struct blob_attr    *tb[MGMTSET_MAX];
    otOperationalDataset dataset;
    uint8_t              tlvs[128];
    long                 value;
    int                  length = 0;
    char                *endptr;

    error = otDatasetGetActive(instance, &dataset);
    if (error != OT_ERROR_NONE)
    {
        goto exit;
    }

    blobmsg_parse(mgmtsetPolicy, MGMTSET_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (tb[MGMTSET_NETWORKKEY] != nullptr)
    {
        dataset.mComponents.mIsNetworkKeyPresent = true;
        length = HexStringToBytes(blobmsg_get_string(tb[MGMTSET_NETWORKKEY]),
                                  dataset.mNetworkKey.m8,
                                  sizeof(dataset.mNetworkKey.m8));
        if (length != OT_NETWORK_KEY_SIZE)
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
        length = 0;
    }

    if (tb[MGMTSET_NETWORKNAME] != nullptr)
    {
        dataset.mComponents.mIsNetworkNamePresent = true;
        length = static_cast<int>(strlen(blobmsg_get_string(tb[MGMTSET_NETWORKNAME])));
        if (length > OT_NETWORK_NAME_MAX_SIZE)
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
        memset(&dataset.mNetworkName, 0, sizeof(dataset.mNetworkName));
        memcpy(dataset.mNetworkName.m8, blobmsg_get_string(tb[MGMTSET_NETWORKNAME]), static_cast<size_t>(length));
        length = 0;
    }

    if (tb[MGMTSET_EXTPANID] != nullptr)
    {
        dataset.mComponents.mIsExtendedPanIdPresent = true;
        if (HexStringToBytes(blobmsg_get_string(tb[MGMTSET_EXTPANID]),
                             dataset.mExtendedPanId.m8,
                             sizeof(dataset.mExtendedPanId.m8)) != OT_EXT_PAN_ID_SIZE)
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
    }

    if (tb[MGMTSET_PANID] != nullptr)
    {
        const char *panidStr = blobmsg_get_string(tb[MGMTSET_PANID]);
        value = strtol(panidStr, &endptr, 0);
        if (value < 0 || value > 65535 || *endptr != '\0')
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
        dataset.mComponents.mIsPanIdPresent = true;
        dataset.mPanId = static_cast<otPanId>(value);
    }

    if (tb[MGMTSET_CHANNEL] != nullptr)
    {
        const char *channelStr = blobmsg_get_string(tb[MGMTSET_CHANNEL]);
        value = strtol(channelStr, &endptr, 0);
        if (value < 11 || value > 26 || *endptr != '\0')
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
        dataset.mComponents.mIsChannelPresent = true;
        dataset.mChannel = static_cast<uint16_t>(value);
    }

    if (tb[MGMTSET_PSKC] != nullptr)
    {
        dataset.mComponents.mIsPskcPresent = true;
        length = HexStringToBytes(blobmsg_get_string(tb[MGMTSET_PSKC]),
                                  dataset.mPskc.m8,
                                  sizeof(dataset.mPskc.m8));
        if (length != OT_PSKC_MAX_SIZE)
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
        length = 0;
    }

    if (tb[MGMTSET_TIMESTAMP] != nullptr)
    {
        dataset.mActiveTimestamp.mSeconds = blobmsg_get_u32(tb[MGMTSET_TIMESTAMP]);
    }
    else
    {
        dataset.mActiveTimestamp.mSeconds++;
    }

    // Stop commissioner if it's running
    if (otCommissionerGetState(instance) == OT_COMMISSIONER_STATE_ACTIVE)
    {
        otCommissionerStop(instance);
    }

    error = SetOrSendActiveDataset(instance, &dataset, tlvs, static_cast<uint8_t>(length));

exit:
    blobmsg_add_u32(&mBuf, "Error", error);
    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== setdataset (set dataset with passphrase or direct dataset TLVs) ========
// ubus call otbr-agent setdataset '{"passphrase":"xxx","networkname":"xxx","extpanid":"xxx"}'
//   or
// ubus call otbr-agent setdataset '{"dataset":"hex_string_of_dataset_tlvs"}'
// Sets the Thread Active Dataset using either:
//   1) passphrase to generate PSKc (with optional networkname/extpanid), or
//   2) direct dataset TLVs as hex string
// All parameters are optional. If no parameters provided, returns error.

int UbusAgentExt::HandleSetDataset(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().SetDatasetDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetDatasetDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest,
                                   struct blob_attr         *aMsg)
{
    blob_buf_init(&mBuf, 0);

    std::lock_guard<std::mutex> lock(*mNcpThreadMutex);
    otInstance                 *instance = mController->GetInstance();

    otError              error = OT_ERROR_NONE;
    struct blob_attr    *tb[SETDATASET_MAX];
    otOperationalDataset dataset;
    otOperationalDatasetTlvs datasetTlvs;
    uint8_t              tlvs[128];
    int                  length = 0;

    blobmsg_parse(setDatasetPolicy, SETDATASET_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    // Mode 1: Direct dataset TLVs as hex string (highest priority)
    if (tb[SETDATASET_DATASET] != nullptr)
    {
        const char *datasetHex = blobmsg_get_string(tb[SETDATASET_DATASET]);
        length = HexStringToBytes(datasetHex, datasetTlvs.mTlvs, sizeof(datasetTlvs.mTlvs));
        if (length < 0 || length > OT_OPERATIONAL_DATASET_MAX_LENGTH)
        {
            error = OT_ERROR_PARSE;
            goto exit;
        }
        datasetTlvs.mLength = static_cast<uint8_t>(length);

        // Stop commissioner if it's running
        if (otCommissionerGetState(instance) == OT_COMMISSIONER_STATE_ACTIVE)
        {
            otCommissionerStop(instance);
        }

        // Set the dataset TLVs directly
        error = otDatasetSetActiveTlvs(instance, &datasetTlvs);
        goto exit;
    }

    error = otDatasetGetActive(instance, &dataset);
    if (error != OT_ERROR_NONE)
    {
        goto exit;
    }

    // Mode 2: Generate PSKc from passphrase (if passphrase provided)
    if (tb[SETDATASET_PASSPHRASE] != nullptr)
    {
        const char *passphrase = blobmsg_get_string(tb[SETDATASET_PASSPHRASE]);

        // Get network name - from parameter or existing dataset
        const char *networkName = nullptr;
        if (tb[SETDATASET_NETWORKNAME] != nullptr)
        {
            networkName = blobmsg_get_string(tb[SETDATASET_NETWORKNAME]);
        }
        else if (dataset.mComponents.mIsNetworkNamePresent)
        {
            networkName = dataset.mNetworkName.m8;
        }
        else
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }

        // Get extended PAN ID - from parameter or existing dataset
        const uint8_t *extPanId = nullptr;
        uint8_t       extPanIdBuf[OT_EXT_PAN_ID_SIZE];
        if (tb[SETDATASET_EXTPANID] != nullptr)
        {
            if (HexStringToBytes(blobmsg_get_string(tb[SETDATASET_EXTPANID]),
                                 extPanIdBuf,
                                 sizeof(extPanIdBuf)) != OT_EXT_PAN_ID_SIZE)
            {
                error = OT_ERROR_PARSE;
                goto exit;
            }
            extPanId = extPanIdBuf;
        }
        else if (dataset.mComponents.mIsExtendedPanIdPresent)
        {
            extPanId = dataset.mExtendedPanId.m8;
        }
        else
        {
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }

        // Generate PSKc from passphrase, network name, and extended PAN ID
        otbr::Psk::Pskc pskcComputer;
        const uint8_t *pskc = pskcComputer.ComputePskc(extPanId, networkName, passphrase);

        // Set PSKc in dataset
        dataset.mComponents.mIsPskcPresent = true;
        memcpy(dataset.mPskc.m8, pskc, OT_PSKC_MAX_SIZE);

        // Update network name if provided
        if (tb[SETDATASET_NETWORKNAME] != nullptr)
        {
            dataset.mComponents.mIsNetworkNamePresent = true;
            length = static_cast<int>(strlen(networkName));
            if (length > OT_NETWORK_NAME_MAX_SIZE)
            {
                error = OT_ERROR_PARSE;
                goto exit;
            }
            memset(&dataset.mNetworkName, 0, sizeof(dataset.mNetworkName));
            memcpy(dataset.mNetworkName.m8, networkName, static_cast<size_t>(length));
        }

        // Update extended PAN ID if provided
        if (tb[SETDATASET_EXTPANID] != nullptr)
        {
            dataset.mComponents.mIsExtendedPanIdPresent = true;
            memcpy(dataset.mExtendedPanId.m8, extPanId, OT_EXT_PAN_ID_SIZE);
        }
    }
    else
    {
        // No passphrase provided - check if any other parameters are provided
        bool hasAnyParam = (tb[SETDATASET_NETWORKNAME] != nullptr) ||
                           (tb[SETDATASET_EXTPANID] != nullptr);
        if (!hasAnyParam)
        {
            // No parameters provided at all
            error = OT_ERROR_INVALID_ARGS;
            goto exit;
        }

        // Only networkname/extpanid provided without passphrase - just update those fields
        if (tb[SETDATASET_NETWORKNAME] != nullptr)
        {
            const char *networkName = blobmsg_get_string(tb[SETDATASET_NETWORKNAME]);
            dataset.mComponents.mIsNetworkNamePresent = true;
            length = static_cast<int>(strlen(networkName));
            if (length > OT_NETWORK_NAME_MAX_SIZE)
            {
                error = OT_ERROR_PARSE;
                goto exit;
            }
            memset(&dataset.mNetworkName, 0, sizeof(dataset.mNetworkName));
            memcpy(dataset.mNetworkName.m8, networkName, static_cast<size_t>(length));
            length = 0;
        }

        if (tb[SETDATASET_EXTPANID] != nullptr)
        {
            if (HexStringToBytes(blobmsg_get_string(tb[SETDATASET_EXTPANID]),
                                 dataset.mExtendedPanId.m8,
                                 sizeof(dataset.mExtendedPanId.m8)) != OT_EXT_PAN_ID_SIZE)
            {
                error = OT_ERROR_PARSE;
                goto exit;
            }
            dataset.mComponents.mIsExtendedPanIdPresent = true;
        }
    }

    // Increment timestamp
    dataset.mActiveTimestamp.mSeconds++;

    // Stop commissioner if it's running
    if (otCommissionerGetState(instance) == OT_COMMISSIONER_STATE_ACTIVE)
    {
        otCommissionerStop(instance);
    }

    error = SetOrSendActiveDataset(instance, &dataset, tlvs, static_cast<uint8_t>(length));

exit:
    blobmsg_add_u32(&mBuf, "Error", error);
    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== discover (MLE Thread Discovery Scan) =========================
// ubus call otbr-agent discover '{"channel":11}'
//   or
// ubus call otbr-agent discover  (scan all channels)
// Performs an MLE Thread Discovery scan and returns discovered networks

// Structure to pass scan parameters and results
struct DiscoverContext
{
    struct ubus_context      *aContext;
    struct ubus_request_data *aRequest;
    struct blob_buf           buf;
    otActiveScanResult        results[27]; // Max 16 channels, but use 27 for safety
    int                       resultCount;
    volatile bool             completed;
};

// Static callback for otThreadDiscover
// Called from OpenThread stack context (NCP thread)
static void HandleDiscoverScanResult(otActiveScanResult *aResult, void *aContext)
{
    DiscoverContext *ctx = static_cast<DiscoverContext *>(aContext);

    if (aResult == nullptr)
    {
        // Scan completed, send reply
        void *scanListArray = blobmsg_open_array(&ctx->buf, "ScanList");

        for (int i = 0; i < ctx->resultCount; i++)
        {
            const otActiveScanResult &result = ctx->results[i];
            void *entry = blobmsg_open_table(&ctx->buf, NULL);

            // PanId
            char panIdStr[8];
            snprintf(panIdStr, sizeof(panIdStr), "0x%04x", result.mPanId);
            blobmsg_add_string(&ctx->buf, "PanId", panIdStr);

            // Rssi
            blobmsg_add_u32(&ctx->buf, "Rssi", static_cast<uint32_t>(result.mRssi));

            // NetworkName
            blobmsg_add_string(&ctx->buf, "NetworkName", result.mNetworkName.m8);

            // Extaddr (no colons)
            char extAddrStr[OT_EXT_ADDRESS_SIZE * 2 + 1] = {0};
            for (int j = 0; j < OT_EXT_ADDRESS_SIZE; j++)
            {
                char byteStr[4];
                snprintf(byteStr, sizeof(byteStr), "%02x", result.mExtAddress.m8[j]);
                strcat(extAddrStr, byteStr);
            }
            blobmsg_add_string(&ctx->buf, "Extaddr", extAddrStr);

            // ExtendedPanId (no colons)
            char extPanIdStr[OT_EXT_PAN_ID_SIZE * 2 + 1] = {0};
            for (int j = 0; j < OT_EXT_PAN_ID_SIZE; j++)
            {
                char byteStr[4];
                snprintf(byteStr, sizeof(byteStr), "%02x", result.mExtendedPanId.m8[j]);
                strcat(extPanIdStr, byteStr);
            }
            blobmsg_add_string(&ctx->buf, "ExtendedPanId", extPanIdStr);

            // Channel
            blobmsg_add_u32(&ctx->buf, "Channel", result.mChannel);

            // Lqi
            blobmsg_add_u32(&ctx->buf, "Lqi", result.mLqi);

            blobmsg_close_table(&ctx->buf, entry);
        }

        blobmsg_close_array(&ctx->buf, scanListArray);

        ubus_send_reply(ctx->aContext, ctx->aRequest, ctx->buf.head);

        blob_buf_free(&ctx->buf);
        ctx->completed = true;
        return;
    }

    // Add result to the array
    if (ctx->resultCount < 27)
    {
        ctx->results[ctx->resultCount++] = *aResult;
    }
}

int UbusAgentExt::HandleDiscover(struct ubus_context      *aContext,
                                 struct ubus_object       *aObj,
                                 struct ubus_request_data *aRequest,
                                 const char               *aMethod,
                                 struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().DiscoverDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::DiscoverDetail(struct ubus_context      *aContext,
                                 struct ubus_request_data *aRequest,
                                 struct blob_attr         *aMsg)
{
    otError error = OT_ERROR_NONE;
    uint32_t scanChannels = 0;

    mNcpThreadMutex->lock();

    otInstance *instance = mController->GetInstance();

    // Check if discover is already in progress
    if (otThreadIsDiscoverInProgress(instance))
    {
        blob_buf_init(&mBuf, 0);
        blobmsg_add_u32(&mBuf, "Error", OT_ERROR_BUSY);
        blobmsg_add_string(&mBuf, "Message", "Discover already in progress");
        ubus_send_reply(aContext, aRequest, mBuf.head);
        mNcpThreadMutex->unlock();
        return 0;
    }

    // Parse optional channel parameter
    struct blob_attr *tb[DISCOVER_MAX];
    blobmsg_parse(discoverPolicy, DISCOVER_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (tb[DISCOVER_CHANNEL])
    {
        uint8_t channel = blobmsg_get_u32(tb[DISCOVER_CHANNEL]);
        if (channel >= 11 && channel <= 26)
        {
            scanChannels = (1 << channel);
        }
    }

    // Ensure the IPv6 interface is up before scanning (equivalent to `ot-ctl ifconfig up`)
    if (!otIp6IsEnabled(instance))
    {
        error = otIp6SetEnabled(instance, true);
        if (error != OT_ERROR_NONE)
        {
            blob_buf_init(&mBuf, 0);
            blobmsg_add_string(&mBuf, "Error", "ifconfig_up_failed");
            blobmsg_add_string(&mBuf, "Message", otThreadErrorToString(error));
            ubus_send_reply(aContext, aRequest, mBuf.head);
            mNcpThreadMutex->unlock();
            return 0;
        }
    }

    // Create context for scan results
    DiscoverContext *ctx = new DiscoverContext();
    ctx->aContext = aContext;
    ctx->aRequest = aRequest;
    ctx->completed = false;
    ctx->resultCount = 0;
    blob_buf_init(&ctx->buf, 0);

    // Start MLE Thread Discovery
    // Parameters: scanChannels=0 means all channels, PanId=BROADCAST, Joiner=false, Eui64Filtering=false
    error = otThreadDiscover(instance, scanChannels, OT_PANID_BROADCAST, false, false,
                             HandleDiscoverScanResult, ctx);

    if (error != OT_ERROR_NONE)
    {
        blob_buf_free(&ctx->buf);
        delete ctx;
        blob_buf_init(&mBuf, 0);
        blobmsg_add_u32(&mBuf, "Error", error);
        ubus_send_reply(aContext, aRequest, mBuf.head);
        mNcpThreadMutex->unlock();
        return 0;
    }

    // Unlock mutex to allow OpenThread to process scan results
    mNcpThreadMutex->unlock();

    // Wait for scan to complete (max 10 seconds)
    // Check every 100ms
    for (int i = 0; i < 100 && !ctx->completed; i++)
    {
        usleep(100000); // 100ms
    }

    // If still not completed after timeout, send error
    if (!ctx->completed)
    {
        blob_buf_init(&mBuf, 0);
        blobmsg_add_u32(&mBuf, "Error", OT_ERROR_FAILED);
        blobmsg_add_string(&mBuf, "Message", "Discover timeout");
        ubus_send_reply(aContext, aRequest, mBuf.head);
        delete ctx;
        return 0;
    }

    // Reply already sent in callback
    delete ctx;
    return 0;
}

// =================== setsrpsrvconfig (set SRP server config) =========================
// ubus call otbr-agent setsrpsrvconfig '{"enabled":true}'
// Alias for setsrpserver - sets the SRP server configuration

int UbusAgentExt::HandleSetSrpServerConfig(struct ubus_context      *aContext,
                                           struct ubus_object       *aObj,
                                           struct ubus_request_data *aRequest,
                                           const char               *aMethod,
                                           struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().SetSrpServerConfigDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetSrpServerConfigDetail(struct ubus_context      *aContext,
                                           struct ubus_request_data *aRequest,
                                           struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aRequest);

    // Forward to SetSrpServerDetail which handles the same functionality
    return SetSrpServerDetail(aContext, aRequest, aMsg);
}

// =================== bufferinfo (get message buffer information) =========================
// ubus call otbr-agent bufferinfo
// Returns message buffer information similar to ot-ctl bufferinfo
//
// Output format (matches ot-ctl bufferinfo):
//   total: 40
//   free: 40
//   max-used: 5
//   6lo send: 0 0 0
//   6lo reas: 0 0 0
//   ip6: 0 0 0
//   mpl: 0 0 0
//   mle: 0 0 0
//   coap: 0 0 0
//   coap secure: 0 0 0
//   application coap: 0 0 0

int UbusAgentExt::HandleBufferInfo(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().BufferInfoDetail(aContext, aRequest);
}

int UbusAgentExt::BufferInfoDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otBufferInfo bufferInfo;
    otMessageGetBufferInfo(instance, &bufferInfo);

    // Basic buffer info
    blobmsg_add_u16(&mBuf, "TotalBuffers", bufferInfo.mTotalBuffers);
    blobmsg_add_u16(&mBuf, "FreeBuffers", bufferInfo.mFreeBuffers);
    blobmsg_add_u16(&mBuf, "MaxUsedBuffers", bufferInfo.mMaxUsedBuffers);

    // Queue info: [numMessages, numBuffers, totalBytes]
    // 6lo send queue
    void *p6loSend = blobmsg_open_array(&mBuf, "6loSendQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.m6loSendQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.m6loSendQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.m6loSendQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, p6loSend);

    // 6lo reassembly queue
    void *p6loReas = blobmsg_open_array(&mBuf, "6loReassemblyQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.m6loReassemblyQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.m6loReassemblyQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.m6loReassemblyQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, p6loReas);

    // IPv6 queue
    void *pIp6 = blobmsg_open_array(&mBuf, "Ip6Queue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mIp6Queue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mIp6Queue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.mIp6Queue.mTotalBytes);
    blobmsg_close_array(&mBuf, pIp6);

    // MPL queue
    void *pMpl = blobmsg_open_array(&mBuf, "MplQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mMplQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mMplQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.mMplQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, pMpl);

    // MLE queue
    void *pMle = blobmsg_open_array(&mBuf, "MleQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mMleQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mMleQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.mMleQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, pMle);

    // CoAP queue
    void *pCoap = blobmsg_open_array(&mBuf, "CoapQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mCoapQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mCoapQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.mCoapQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, pCoap);

    // CoAP Secure queue
    void *pCoapSecure = blobmsg_open_array(&mBuf, "CoapSecureQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mCoapSecureQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mCoapSecureQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.mCoapSecureQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, pCoapSecure);

    // Application CoAP queue
    void *pAppCoap = blobmsg_open_array(&mBuf, "ApplicationCoapQueue");
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mApplicationCoapQueue.mNumMessages);
    blobmsg_add_u16(&mBuf, nullptr, bufferInfo.mApplicationCoapQueue.mNumBuffers);
    blobmsg_add_u32(&mBuf, nullptr, bufferInfo.mApplicationCoapQueue.mTotalBytes);
    blobmsg_close_array(&mBuf, pAppCoap);

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== txpower (get transmit power) =========================
// ubus call otbr-agent txpower
// Returns the current transmit power in dBm
//
// Output format:
//   { "power": -10 }

int UbusAgentExt::HandleTxPower(struct ubus_context      *aContext,
                                struct ubus_object       *aObj,
                                struct ubus_request_data *aRequest,
                                const char               *aMethod,
                                struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    OT_UNUSED_VARIABLE(aMsg);
    return GetInstance().TxPowerDetail(aContext, aRequest);
}

int UbusAgentExt::TxPowerDetail(struct ubus_context      *aContext,
                                struct ubus_request_data *aRequest)
{
    blob_buf_init(&mBuf, 0);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    int8_t power;
    otError error = otPlatRadioGetTransmitPower(instance, &power);

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_u16(&mBuf, "power", power);
    }
    else
    {
        blobmsg_add_u32(&mBuf, "error", error);
        blobmsg_add_string(&mBuf, "message", "Failed to get transmit power");
    }

    mNcpThreadMutex->unlock();

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

// =================== settxpower (set transmit power) =========================
// ubus call otbr-agent settxpower '{"power":-10}'
// Sets the transmit power in dBm
//
// Output format:
//   { "success": true } or { "error": <code>, "message": "..." }

int UbusAgentExt::HandleSetTxPower(struct ubus_context      *aContext,
                                   struct ubus_object       *aObj,
                                   struct ubus_request_data *aRequest,
                                   const char               *aMethod,
                                   struct blob_attr         *aMsg)
{
    OT_UNUSED_VARIABLE(aObj);
    OT_UNUSED_VARIABLE(aMethod);
    return GetInstance().SetTxPowerDetail(aContext, aRequest, aMsg);
}

int UbusAgentExt::SetTxPowerDetail(struct ubus_context      *aContext,
                                   struct ubus_request_data *aRequest,
                                   struct blob_attr         *aMsg)
{
    blob_buf_init(&mBuf, 0);

    struct blob_attr *tb[SET_TX_POWER_MAX];
    blobmsg_parse(setTxPowerPolicy, SET_TX_POWER_MAX, tb, blob_data(aMsg), blob_len(aMsg));

    if (!tb[SET_TX_POWER])
    {
        blobmsg_add_u32(&mBuf, "error", OT_ERROR_INVALID_ARGS);
        blobmsg_add_string(&mBuf, "message", "Missing 'power' parameter");
        ubus_send_reply(aContext, aRequest, mBuf.head);
        return 0;
    }

    int8_t power = blobmsg_get_u32(tb[SET_TX_POWER]);

    mNcpThreadMutex->lock();
    otInstance *instance = mController->GetInstance();

    otError error = otPlatRadioSetTransmitPower(instance, power);

    mNcpThreadMutex->unlock();

    if (error == OT_ERROR_NONE)
    {
        blobmsg_add_u8(&mBuf, "success", 1);
        blobmsg_add_u16(&mBuf, "power", power);
    }
    else
    {
        blobmsg_add_u32(&mBuf, "error", error);
        blobmsg_add_string(&mBuf, "message", "Failed to set transmit power");
    }

    ubus_send_reply(aContext, aRequest, mBuf.head);
    return 0;
}

} // namespace ubus
} // namespace otbr
