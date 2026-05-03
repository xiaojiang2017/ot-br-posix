/*
 *  Copyright (c) 2024, Custom OpenThread Border Router Extension.
 *  All rights reserved.
 *
 *  This file is an independent extension for ot-br-posix.
 *  It registers a separate "otbr-agent" ubus object to avoid
 *  conflicts with the official "otbr" ubus object.
 */

/**
 * @file
 * This file includes definitions for the custom otbr-agent ubus API.
 *
 * Usage:
 *   ubus call otbr-agent version
 *   ubus call otbr-agent status
 *   ubus call otbr-agent threadinfo
 *   ubus call otbr-agent getaddrs
 *   ubus call otbr-agent dataset '{"type":"active"}'
 *   ubus call otbr-agent topology
 *   ubus call otbr-agent getevents '{"count":20}'
 *   ubus call otbr-agent bbr
 *   ubus call otbr-agent nat64
 *   ubus call otbr-agent srpserver
 *   ubus call otbr-agent meshdiag                     (full mesh diagnostic: topology + childtable + childip6 + routerneighbortable)
 *   ubus call otbr-agent meshdiag '{"rloc16":25600}'  (targeted single-router diagnostic: childtable + childip6 by default)
 *   ubus call otbr-agent uciconfig                    (read UCI config and return current settings)
 *   ubus call otbr-agent uciapply                     (re-read UCI config, set dataset, start Thread)
 *
 * Events (listen via: ubus listen otbr-agent.*):
 *   otbr-agent.state     - role/network state changes
 *   otbr-agent.neighbor  - direct neighbor table changes (child/router add/remove)
 *   otbr-agent.topology  - network-wide router/child topology changes
 */

#ifndef OTBR_AGENT_OTUBUS_AGENT_HPP_
#define OTBR_AGENT_OTUBUS_AGENT_HPP_

#include "openthread-br/config.h"

#include <deque>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include <openthread/dataset.h>
#include <openthread/dns_client.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/backbone_router.h>
#include <openthread/backbone_router_ftd.h>
#include <openthread/border_agent.h>
#include <openthread/border_routing.h>
#include <openthread/commissioner.h>
#include <openthread/joiner.h>
#include <openthread/logging.h>
#include <openthread/nat64.h>
#include <openthread/srp_server.h>
#include <openthread/dnssd_server.h>
#include <openthread/mesh_diag.h>

#include "ncp/rcp_host.hpp"
#include "utils/pskc.hpp"

namespace otbr {
class BorderAgent;
}

extern "C" {
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <uci.h>
}

namespace otbr {
namespace ubus {

/**
 * Maximum number of events to keep in the ring buffer.
 */
static constexpr size_t kMaxEventLogSize = 100;

/**
 * Represents a single event log entry.
 */
struct EventLogEntry
{
    time_t      mTimestamp;
    std::string mType;    // "state" or "neighbor"
    std::string mDetail;  // JSON-like description
};

/**
 * Represents a pending ubus event to be sent from the ubus thread.
 * Events are queued from any thread and drained in the ubus uloop context.
 */
struct PendingUbusEvent
{
    std::string mEventName;
    std::string mJsonData;  // serialized blob as JSON string
};

/**
 * @class UbusAgentExt
 *
 * This class implements a custom "otbr-agent" ubus object,
 * completely independent from the official UbusServer ("otbr" object).
 *
 * Features:
 *   - Standard query methods (version/status/threadinfo/getaddrs/dataset/topology)
 *   - State change callback (otSetStateChangedCallback) — monitors role, network, dataset changes
 *   - Neighbor table callback (otThreadRegisterNeighborTableCallback) — monitors direct child/router add/remove
 *   - Topology scan — periodically scans all routers/children in the network via OT API
 *   - ubus event broadcast — subscribers receive real-time events via `ubus listen`
 *   - Event log query — `ubus call otbr-agent getevents` returns recent events
 */
class UbusAgentExt
{
public:
    /**
     * Initialize the singleton instance.
     *
     * @param[in] aController  A pointer to the NCP controller.
     * @param[in] aMutex       A pointer to the NCP thread mutex.
     */
    static void Initialize(Ncp::RcpHost *aController, std::mutex *aMutex);

    /**
     * Get the singleton instance.
     *
     * @returns Reference to the singleton.
     */
    static UbusAgentExt &GetInstance(void);

    /**
     * Register the "otbr-agent" ubus object on the given ubus context.
     * Also registers OpenThread callbacks for state and neighbor changes.
     *
     * @param[in] aContext  The ubus context to add the object to.
     *
     * @returns 0 on success, -1 on failure.
     */
    int RegisterObject(struct ubus_context *aContext);

    /**
     * Register OpenThread callbacks (state change + neighbor table).
     * Must be called from the NCP thread context (after OT instance is initialized).
     */
    void RegisterOtCallbacks(void);

    // ---- ubus method handlers (static, forwarding to instance) ----

    static int HandleVersion(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleStatus(struct ubus_context *aContext, struct ubus_object *aObj,
                            struct ubus_request_data *aRequest, const char *aMethod,
                            struct blob_attr *aMsg);

    static int HandleThreadInfo(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleRloc16(struct ubus_context *aContext, struct ubus_object *aObj,
                            struct ubus_request_data *aRequest, const char *aMethod,
                            struct blob_attr *aMsg);

    static int HandleGetAddrs(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    static int HandleDataset(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleTopology(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    static int HandleGetEvents(struct ubus_context *aContext, struct ubus_object *aObj,
                               struct ubus_request_data *aRequest, const char *aMethod,
                               struct blob_attr *aMsg);

    static int HandleBbr(struct ubus_context *aContext, struct ubus_object *aObj,
                         struct ubus_request_data *aRequest, const char *aMethod,
                         struct blob_attr *aMsg);

    static int HandleNat64(struct ubus_context *aContext, struct ubus_object *aObj,
                           struct ubus_request_data *aRequest, const char *aMethod,
                           struct blob_attr *aMsg);

    static int HandleUciConfig(struct ubus_context *aContext, struct ubus_object *aObj,
                               struct ubus_request_data *aRequest, const char *aMethod,
                               struct blob_attr *aMsg);

    static int HandleUciApply(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    static int HandleLeaderData(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleJoinerState(struct ubus_context *aContext, struct ubus_object *aObj,
                                 struct ubus_request_data *aRequest, const char *aMethod,
                                 struct blob_attr *aMsg);

    static int HandleJoinerStart(struct ubus_context *aContext, struct ubus_object *aObj,
                                 struct ubus_request_data *aRequest, const char *aMethod,
                                 struct blob_attr *aMsg);

    static int HandleJoinerStop(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleSetMdns(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleCommissionerStart(struct ubus_context *aContext, struct ubus_object *aObj,
                                       struct ubus_request_data *aRequest, const char *aMethod,
                                       struct blob_attr *aMsg);

    static int HandleCommissionerStop(struct ubus_context *aContext, struct ubus_object *aObj,
                                      struct ubus_request_data *aRequest, const char *aMethod,
                                      struct blob_attr *aMsg);

    static int HandleSetBbr(struct ubus_context *aContext, struct ubus_object *aObj,
                            struct ubus_request_data *aRequest, const char *aMethod,
                            struct blob_attr *aMsg);

    static int HandleSetSrpServer(struct ubus_context *aContext, struct ubus_object *aObj,
                                  struct ubus_request_data *aRequest, const char *aMethod,
                                  struct blob_attr *aMsg);

    static int HandleSetSrpUnicast(struct ubus_context *aContext, struct ubus_object *aObj,
                                   struct ubus_request_data *aRequest, const char *aMethod,
                                   struct blob_attr *aMsg);

    static int HandleGetSrpUnicast(struct ubus_context *aContext, struct ubus_object *aObj,
                                   struct ubus_request_data *aRequest, const char *aMethod,
                                   struct blob_attr *aMsg);

    static int HandleSetNat64(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    static int HandleOmrPrefix(struct ubus_context *aContext, struct ubus_object *aObj,
                               struct ubus_request_data *aRequest, const char *aMethod,
                               struct blob_attr *aMsg);

    static int HandleOnLinkPrefix(struct ubus_context *aContext, struct ubus_object *aObj,
                                  struct ubus_request_data *aRequest, const char *aMethod,
                                  struct blob_attr *aMsg);

    static int HandleMeshDiag(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    // Additional ubus methods from patch reference
    static int HandleSrpsrvconfig(struct ubus_context *aContext, struct ubus_object *aObj,
                                  struct ubus_request_data *aRequest, const char *aMethod,
                                  struct blob_attr *aMsg);

    static int HandleSrpsrvservice(struct ubus_context *aContext, struct ubus_object *aObj,
                                   struct ubus_request_data *aRequest, const char *aMethod,
                                   struct blob_attr *aMsg);

    static int HandleSrpNetService(struct ubus_context *aContext, struct ubus_object *aObj,
                                   struct ubus_request_data *aRequest, const char *aMethod,
                                   struct blob_attr *aMsg);

    static int HandleServices(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    static int HandleMetrics(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleNetdata(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleNeighbortable(struct ubus_context *aContext, struct ubus_object *aObj,
                                   struct ubus_request_data *aRequest, const char *aMethod,
                                   struct blob_attr *aMsg);

    static int HandleNat64status(struct ubus_context *aContext, struct ubus_object *aObj,
                                 struct ubus_request_data *aRequest, const char *aMethod,
                                 struct blob_attr *aMsg);

    static int HandleGetprefix(struct ubus_context *aContext, struct ubus_object *aObj,
                               struct ubus_request_data *aRequest, const char *aMethod,
                               struct blob_attr *aMsg);

    static int HandleGetOmrPrefix(struct ubus_context *aContext, struct ubus_object *aObj,
                                  struct ubus_request_data *aRequest, const char *aMethod,
                                  struct blob_attr *aMsg);

    static int HandleRouterlist(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleCommissionerstate(struct ubus_context *aContext, struct ubus_object *aObj,
                                       struct ubus_request_data *aRequest, const char *aMethod,
                                       struct blob_attr *aMsg);

    static int HandleSetnetworkconfig(struct ubus_context *aContext, struct ubus_object *aObj,
                                      struct ubus_request_data *aRequest, const char *aMethod,
                                      struct blob_attr *aMsg);

    static int HandleState(struct ubus_context *aContext, struct ubus_object *aObj,
                           struct ubus_request_data *aRequest, const char *aMethod,
                           struct blob_attr *aMsg);

    static int HandlePskc(struct ubus_context *aContext, struct ubus_object *aObj,
                          struct ubus_request_data *aRequest, const char *aMethod,
                          struct blob_attr *aMsg);

    static int HandleThreadStart(struct ubus_context *aContext, struct ubus_object *aObj,
                                 struct ubus_request_data *aRequest, const char *aMethod,
                                 struct blob_attr *aMsg);

    static int HandleThreadStop(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleJoinerNum(struct ubus_context *aContext, struct ubus_object *aObj,
                               struct ubus_request_data *aRequest, const char *aMethod,
                               struct blob_attr *aMsg);

    static int HandleSetLeaderRole(struct ubus_context *aContext, struct ubus_object *aObj,
                                   struct ubus_request_data *aRequest, const char *aMethod,
                                   struct blob_attr *aMsg);

    static int HandleMgmtset(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleSetDataset(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleSetSrpServerConfig(struct ubus_context *aContext, struct ubus_object *aObj,
                                        struct ubus_request_data *aRequest, const char *aMethod,
                                        struct blob_attr *aMsg);

    static int HandleDiscover(struct ubus_context *aContext, struct ubus_object *aObj,
                              struct ubus_request_data *aRequest, const char *aMethod,
                              struct blob_attr *aMsg);

    static int HandleBufferInfo(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleTxPower(struct ubus_context *aContext, struct ubus_object *aObj,
                             struct ubus_request_data *aRequest, const char *aMethod,
                             struct blob_attr *aMsg);

    static int HandleSetTxPower(struct ubus_context *aContext, struct ubus_object *aObj,
                                struct ubus_request_data *aRequest, const char *aMethod,
                                struct blob_attr *aMsg);

    static int HandleJoinerAdd(struct ubus_context *aContext, struct ubus_object *aObj,
                               struct ubus_request_data *aRequest, const char *aMethod,
                               struct blob_attr *aMsg);

    static int HandleJoinerRemove(struct ubus_context *aContext, struct ubus_object *aObj,
                                  struct ubus_request_data *aRequest, const char *aMethod,
                                  struct blob_attr *aMsg);

#if OTBR_ENABLE_BORDER_AGENT
    void SetBorderAgent(BorderAgent *aBorderAgent);
#endif

    // ---- OpenThread callbacks (static) ----

    /**
     * State changed callback registered via mController->AddThreadStateChangedCallback().
     * Called from the NCP main loop thread.
     */
    void HandleStateChanged(otChangedFlags aFlags);

    /**
     * Neighbor table callback registered via otThreadRegisterNeighborTableCallback().
     * Called from the OpenThread stack context.
     */
    static void HandleNeighborTableChanged(otNeighborTableEvent             aEvent,
                                           const otNeighborTableEntryInfo  *aEntryInfo);

    // Allow static C-style callbacks in the .cpp to call private methods
    friend void JoinerCallback(otError aError, void *aContext);
    friend void CommissionerStateCallback(otCommissionerState aState, void *aContext);
    friend void CommissionerJoinerEventCallback(otCommissionerJoinerEvent aEvent,
                                                const otJoinerInfo      *aJoinerInfo,
                                                const otExtAddress      *aJoinerId,
                                                void                    *aContext);

private:
    UbusAgentExt(Ncp::RcpHost *aController, std::mutex *aMutex);

    // ---- detail implementations ----
    int VersionDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int StatusDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int ThreadInfoDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int Rloc16Detail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int GetAddrsDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int DatasetDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int TopologyDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int GetEventsDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int BbrDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int Nat64Detail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int UciConfigDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int UciApplyDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int LeaderDataDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int JoinerStateDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int JoinerStartDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int JoinerStopDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SetMdnsDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int CommissionerStartDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int CommissionerStopDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SetBbrDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int SetSrpServerDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);

    // SRP unicast supplement: while the SRP server runs in anycast mode on port
    // 53, additionally publish a unicast DNS/SRP service entry pointing to this
    // device's mesh-local EID at the same port, so clients can use either the
    // shared anycast ALOC or the device's unicast address. Reconciled on role /
    // network-data changes (idempotent).
    void UpdateSrpUnicastSupplement(otInstance *aInstance);
    int  SetSrpUnicastDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int  GetSrpUnicastDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SetNat64Detail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int OmrPrefixDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int OnLinkPrefixDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int MeshDiagDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);

    // Additional detail methods from patch reference
    int SrpsrvconfigDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SrpsrvserviceDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SrpNetServiceDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int ServicesDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int MetricsDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int NetdataDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int NeighbortableDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int Nat64statusDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int GetprefixDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int GetOmrPrefixDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int RouterlistDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int CommissionerstateDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SetnetworkconfigDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);

    // Additional methods for state/pskc/thread/joiner
    int StateDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int PskcDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int ThreadStartDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int ThreadStopDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int JoinerNumDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SetLeaderRoleDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int MgmtsetDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int SetDatasetDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int SetSrpServerConfigDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);

    int DiscoverDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int BufferInfoDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int TxPowerDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest);
    int SetTxPowerDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int JoinerAddDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    int JoinerRemoveDetail(struct ubus_context *aContext, struct ubus_request_data *aRequest, struct blob_attr *aMsg);
    void HandleJoinerCallback(otError aError);
    void HandleCommissionerStateChanged(otCommissionerState aState);
    void HandleCommissionerJoinerEvent(otCommissionerJoinerEvent aEvent,
                                       const otJoinerInfo       *aJoinerInfo,
                                       const otExtAddress       *aJoinerId);

    static void HandleSrpNetServiceBrowse(otError aError, const otDnsBrowseResponse *aResponse, void *aContext);
    void        HandleSrpNetServiceBrowse(otError aError, const otDnsBrowseResponse *aResponse);
    static void HandleSrpNetServiceResolve(otError aError, const otDnsServiceResponse *aResponse, void *aContext);
    void        HandleSrpNetServiceResolve(otError aError, const otDnsServiceResponse *aResponse);
    otError     StartNextSrpNetServiceBrowse(void);
    otError     StartNextSrpNetServiceResolve(void);
    void        CompleteSrpNetServiceDeferred(void);

    // ---- UCI configuration helpers ----

    /**
     * Holds Thread network configuration read from UCI.
     */
    struct UciThreadConfig
    {
        bool        mAutoStart;
        bool        mInited;   // true if UCI 'inited' flag is '1' (random init already done)
        bool        mHasLogLevel;
        bool        mHasMdnsServiceConfig;
        bool        mHasNetworkName;
        bool        mHasChannel;
        bool        mHasPanId;
        bool        mHasExtPanId;
        bool        mHasNetworkKey;
        bool        mHasPskc;
        bool        mHasMeshLocalPrefix;
        bool        mHasPassphrase;

        char        mNetworkName[OT_NETWORK_NAME_MAX_SIZE + 1];
        otLogLevel   mLogLevel;
        char        mMdnsInstanceName[65];
        char        mMdnsVendorName[65];
        char        mMdnsProductName[65];
        uint16_t    mChannel;
        uint16_t    mPanId;
        uint8_t     mExtPanId[OT_EXT_PAN_ID_SIZE];
        uint8_t     mNetworkKey[OT_NETWORK_KEY_SIZE];
        uint8_t     mPskc[OT_PSKC_MAX_SIZE];
        uint8_t     mMeshLocalPrefix[8];  // /64 prefix, 8 bytes
        char        mPassphrase[OT_PASSPHRASE_MAX_LENGTH + 1];
    };

    /**
     * Read Thread network config from UCI file /etc/config/otbr-agent.
     *
     * @param[out] aConfig  The parsed configuration.
     *
     * @returns true on success (at least partial config read), false if UCI package not found.
     */
    bool ReadUciConfig(UciThreadConfig &aConfig);

    /**
     * Apply the UCI config to the OpenThread stack: set Active Dataset and optionally start Thread.
     * Must be called with mNcpThreadMutex NOT held (will lock internally).
     *
     * @param[in] aConfig  The parsed configuration.
     *
     * @returns OT_ERROR_NONE on success, or an error code.
     */
    otError ApplyUciConfig(const UciThreadConfig &aConfig);

    /**
     * Helper to parse a hex string into a byte array.
     *
     * @returns The number of bytes parsed, or -1 on error.
     */
    static int HexStringToBytes(const char *aHexStr, uint8_t *aBytes, size_t aMaxLen);

#if OTBR_ENABLE_BORDER_AGENT
    void ApplyPendingMdnsServiceConfig(void);
#endif

    /**
     * Called from RegisterOtCallbacks() to auto-apply UCI config if autostart is enabled.
     */
    void TryAutoStartFromUci(void);

    /**
     * Write 'inited=1' and the factory-assigned EUI64 to UCI config /etc/config/otbr.
     * This marks that random initialization has been completed and persists the
     * device identifier generated/read during first-time setup.
     */
    static bool WriteUciInitedAndEui64(const char *aEui64);

    // ---- callback detail implementations ----
    void HandleNeighborTableChangedDetail(otNeighborTableEvent             aEvent,
                                          const otNeighborTableEntryInfo  *aEntryInfo);
    void SendUbusEvent(const char *aEventName, struct blob_attr *aData);
    void AddEventLog(const std::string &aType, const std::string &aDetail);

    // ---- cross-thread event queue (main thread → ubus thread) ----
    void EnqueueUbusEvent(const char *aEventName, struct blob_attr *aData);
    void DrainPendingEvents(void);
    static void HandleEventDrainTimer(struct uloop_timeout *aTimeout);

    // ---- commissioner timeout ----
    static void HandleCommissionerTimeoutTimer(struct uloop_timeout *aTimeout);
    void CancelCommissionerTimeout(void);

    // ---- meshdiag async state machine ----
    static void HandleMeshDiagDiscoverDone(otError aError, otMeshDiagRouterInfo *aRouterInfo, void *aContext);
    void        HandleMeshDiagDiscoverDone(otError aError, otMeshDiagRouterInfo *aRouterInfo);
    static void HandleMeshDiagChildTableResult(otError aError, const otMeshDiagChildEntry *aChildEntry, void *aContext);
    void        HandleMeshDiagChildTableResult(otError aError, const otMeshDiagChildEntry *aChildEntry);
    static void HandleMeshDiagChildIp6Addrs(otError aError, uint16_t aChildRloc16,
                                            otMeshDiagIp6AddrIterator *aIp6AddrIterator, void *aContext);
    void        HandleMeshDiagChildIp6Addrs(otError aError, uint16_t aChildRloc16,
                                            otMeshDiagIp6AddrIterator *aIp6AddrIterator);
    static void HandleMeshDiagRouterNeighborTableResult(otError aError,
                                                        const otMeshDiagRouterNeighborEntry *aNeighborEntry,
                                                        void *aContext);
    void        HandleMeshDiagRouterNeighborTableResult(otError aError,
                                                        const otMeshDiagRouterNeighborEntry *aNeighborEntry);
    void        AdvanceMeshDiagPhase(void);
    void        CompleteMeshDiagDeferred(void);

    // ---- topology scanning ----
    /**
     * Scan all routers in the Thread network by iterating Router IDs (0..maxRouterId).
     * Compare with previous snapshot to detect added/removed routers.
     * Also scan child table to detect child changes (for FTD nodes).
     * Must be called with mNcpThreadMutex held.
     */
    void ScanNetworkTopology(void);

    /**
     * Represents a known router entry in the topology snapshot.
     */
    struct RouterSnapshot
    {
        uint8_t      mRouterId;
        uint16_t     mRloc16;
        otExtAddress mExtAddress;
        uint8_t      mPathCost;
        bool         mLinkEstablished;
    };

    /**
     * Represents a known child entry in the topology snapshot.
     */
    struct ChildSnapshot
    {
        uint16_t     mRloc16;
        uint16_t     mChildId;
        otExtAddress mExtAddress;
        bool         mRxOnWhenIdle;
        bool         mFullThreadDevice;
    };

    // ---- helpers ----
    const char *RoleToString(otDeviceRole aRole);
    const char *NeighborEventToString(otNeighborTableEvent aEvent);
    void        OutputBytes(const uint8_t *aBytes, uint8_t aLength, char *aOutput);
    void        OutputBytesToUpper(const uint8_t *aBytes, uint8_t aLength, char *aOutput);
    void        AddRloc16ToBlob(struct blob_buf *aBuf, const char *aKey, uint16_t aRloc16);

    Ncp::RcpHost *mController;
    std::mutex                *mNcpThreadMutex;
    struct blob_buf            mBuf;
    struct blob_buf            mEventBuf;       // dedicated buffer for event sending
    struct ubus_context       *mUbusContext;     // saved for sending ubus events
    std::deque<EventLogEntry>  mEventLog;        // ring buffer of recent events
    std::mutex                 mEventLogMutex;   // protects mEventLog (accessed from multiple threads)
    otDeviceRole               mLastRole;        // track role changes
    bool                       mCallbacksRegistered;
    bool                       mSrpUnicastEnabled = true; // publish unicast SRP supplement entry alongside anycast

    // ---- cross-thread event queue ----
    std::queue<PendingUbusEvent> mPendingEvents;      // events queued from main thread
    std::mutex                   mPendingEventsMutex; // protects mPendingEvents
    struct uloop_timeout         mEventDrainTimer;    // uloop timer to drain queue in ubus thread
    struct uloop_timeout         mCommissionerTimeoutTimer; // uloop timer for commissioner auto-stop

    // ---- topology scanning state ----
    std::map<uint8_t, RouterSnapshot>  mKnownRouters;   // key: router ID
    std::map<uint16_t, ChildSnapshot>  mKnownChildren;  // key: RLOC16
    bool                               mTopologyInitialized;
    bool                               mUciApplied; // track whether UCI config has been applied

    // ---- meshdiag deferred request state ----
    enum MeshDiagPhase
    {
        kMeshDiagIdle = 0,
        kMeshDiagTopology,
        kMeshDiagChildTable,
        kMeshDiagChildIp6,
        kMeshDiagRouterNeighbor,
        kMeshDiagComplete,
    };

    struct MeshDiagChildIp6Result
    {
        uint16_t                  mChildRloc16;
        std::vector<otIp6Address> mAddresses;
    };

    struct SrpNetServiceResult
    {
        std::string              mInstance;
        std::string              mServiceName;
        otError                  mError;
        bool                     mResolved;
        uint32_t                 mTtl;
        uint16_t                 mPort;
        uint16_t                 mPriority;
        uint16_t                 mWeight;
        std::string              mHost;
        std::string              mExtAddr;
        otIp6Address             mHostAddress;
        uint32_t                 mHostAddressTtl;
        std::vector<std::string> mTxt;
    };

    struct MeshDiagRouterResult
    {
        // From topology discovery
        uint8_t      mRouterId;
        uint16_t     mRloc16;
        otExtAddress mExtAddress;
        uint16_t     mVersion;
        bool         mIsThisDevice;
        bool         mIsLeader;
        bool         mIsBorderRouter;
        uint8_t      mLinkQualities[OT_NETWORK_MAX_ROUTER_ID + 1];
        std::vector<otIp6Address>        mIp6Addresses;
        std::vector<otMeshDiagChildInfo> mChildren;
        // From childtable query (per-router)
        std::vector<otMeshDiagChildEntry> mChildTable;
        // From childip6 query (per-router)
        std::vector<MeshDiagChildIp6Result> mChildIp6;
        // From routerneighbortable query (per-router)
        std::vector<otMeshDiagRouterNeighborEntry> mRouterNeighbors;
    };

    MeshDiagPhase                mMeshDiagPhase;
    size_t                       mMeshDiagRouterIdx;
    bool                         mMeshDiagDone;
    bool                         mMeshDiagWantChildTable;
    bool                         mMeshDiagWantChildIp6;
    bool                         mMeshDiagWantRouterNeighbor;
    bool                         mMeshDiagTargetMode;      // true when querying a single router by rloc16
    bool                         mMeshDiagTargetResponded; // true if the target answered any query phase
    otError                      mMeshDiagFinalError;
    struct ubus_context         *mMeshDiagUbusCtx;
    struct ubus_request_data     mMeshDiagDeferredReq;
    std::mutex                   mMeshDiagMutex;
    std::vector<MeshDiagRouterResult> mMeshDiagResults;

    // ---- SRP network service discovery deferred request state ----
    std::mutex                       mSrpNetServiceMutex;
    struct ubus_context             *mSrpNetServiceUbusCtx;
    struct ubus_request_data         mSrpNetServiceDeferredReq;
    bool                             mSrpNetServiceBusy;
    bool                             mSrpNetServiceDone;
    bool                             mSrpNetServiceResolve;
    size_t                           mSrpNetServiceResolveIdx;
    otError                          mSrpNetServiceFinalError;
    otDnsQueryConfig                 mSrpNetServiceQueryConfig;
    std::vector<std::string>         mSrpNetServiceNames;
    size_t                           mSrpNetServiceBrowseIdx;
    std::vector<SrpNetServiceResult> mSrpNetServiceResults;
#if OTBR_ENABLE_BORDER_AGENT
    BorderAgent                       *mBorderAgent;
    bool                               mHasPendingMdnsServiceConfig;
    std::string                        mPendingMdnsInstanceName;
    std::string                        mPendingMdnsVendorName;
    std::string                        mPendingMdnsProductName;
#endif
};

} // namespace ubus
} // namespace otbr

#endif // OTBR_AGENT_OTUBUS_AGENT_HPP_
