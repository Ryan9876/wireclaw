export interface paths {
    "/api/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Health */
        get: operations["health_api_health_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/config/capabilities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Capabilities */
        get: operations["capabilities_api_config_capabilities_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Recent Cases */
        get: operations["recent_cases_api_cases_get"];
        put?: never;
        /** Create */
        post: operations["create_api_cases_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Case */
        get: operations["get_case_api_cases__case_id__get"];
        put?: never;
        post?: never;
        /** Delete */
        delete: operations["delete_api_cases__case_id__delete"];
        options?: never;
        head?: never;
        /** Rename Case */
        patch: operations["rename_case_api_cases__case_id__patch"];
        trace?: never;
    };
    "/api/cases/{case_id}/capture": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Capture */
        post: operations["capture_api_cases__case_id__capture_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/investigate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Investigate */
        post: operations["investigate_api_cases__case_id__investigate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/followups": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Followup */
        post: operations["followup_api_cases__case_id__followups_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/capabilities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Capability */
        post: operations["capability_api_cases__case_id__capabilities_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/artifacts/evidence-capture": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Evidence Capture */
        post: operations["evidence_capture_api_cases__case_id__artifacts_evidence_capture_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/bridge-grants": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Bridge Grant */
        post: operations["bridge_grant_api_cases__case_id__bridge_grants_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Evidence */
        get: operations["evidence_api_cases__case_id__evidence_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/evidence/{evidence_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Evidence Item */
        get: operations["evidence_item_api_cases__case_id__evidence__evidence_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Findings */
        get: operations["findings_api_cases__case_id__findings_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/report": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Report */
        get: operations["report_api_cases__case_id__report_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/cases/{case_id}/artifacts/{artifact_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Artifact Metadata */
        get: operations["artifact_metadata_api_cases__case_id__artifacts__artifact_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** AIStatusResponse */
        AIStatusResponse: {
            /**
             * Effective Provider Mode
             * @enum {string}
             */
            effective_provider_mode: "none" | "openai_compatible_cloud" | "openai_compatible_local" | "embedded_local";
            /**
             * Embedded Availability
             * @enum {string}
             */
            embedded_availability: "ready" | "unavailable" | "not_applicable";
            /** Model */
            model: string | null;
            /** Failure Code */
            failure_code: string | null;
        };
        /** ArtifactResponse */
        ArtifactResponse: {
            /** Id */
            id: string;
            /** Kind */
            kind: string;
            /** Sha256 */
            sha256: string;
            /** Bytes */
            bytes: number;
            /** Parent Sha */
            parent_sha: string;
        };
        /** BridgeGrantRequest */
        BridgeGrantRequest: {
            /** Artifact Id */
            artifact_id: string;
            /** Finding Id */
            finding_id: string;
        };
        /** BridgeGrantResponse */
        BridgeGrantResponse: {
            /** Request Id */
            request_id: string;
            /** Token */
            token: string;
            /** Bridge Origin */
            bridge_origin: string;
            /** Expires Unix */
            expires_unix: number;
        };
        /** CapabilitiesResponse */
        CapabilitiesResponse: {
            /** Capabilities */
            capabilities: string[];
            /** Provider Mode */
            provider_mode: string;
            /** Provider Modes Supported By Interface */
            provider_modes_supported_by_interface: string[];
            /** Bridge */
            bridge: {
                [key: string]: string;
            };
            /** Limits */
            limits: {
                [key: string]: number;
            };
            ai: components["schemas"]["AIStatusResponse"];
        };
        /** CapabilityRequest */
        CapabilityRequest: {
            /** Artifact Id */
            artifact_id: string;
            /**
             * Capability
             * @enum {string}
             */
            capability: "get_capture_metadata" | "assess_capture_quality" | "list_protocols" | "list_endpoints" | "list_conversations" | "analyze_dns" | "analyze_tcp_establishment" | "analyze_tcp_health" | "analyze_rtt" | "analyze_window_behavior" | "analyze_tcp_resets" | "analyze_throughput" | "analyze_mss" | "analyze_fragmentation" | "analyze_pmtud_signals" | "analyze_tls_handshakes" | "analyze_http_timing";
            /** Tcp Stream */
            tcp_stream?: number | null;
        };
        /** CaseResponse */
        CaseResponse: {
            /** Id */
            id: string;
            /** Name */
            name: string;
            /** Capture Name */
            capture_name: string | null;
            /** Display Name */
            display_name: string | null;
            /** Symptom */
            symptom: string;
            /** State */
            state: string;
            /** Created */
            created: string;
            /** Updated */
            updated: string;
            /** Capture Sha */
            capture_sha: string | null;
            /** Original Id */
            original_id: string | null;
            /** Quality */
            quality: string | null;
            /** Last Error */
            last_error: string | null;
            /** History */
            history: components["schemas"]["HistoryResponse"][];
            /** Runs */
            runs: components["schemas"]["RunResponse"][];
            /** Artifacts */
            artifacts: components["schemas"]["ArtifactResponse"][];
            /** Evidence Count */
            evidence_count: number;
            /** Gate Boundary */
            gate_boundary: string;
            /** Provider Mode */
            provider_mode: string;
            ai_status: components["schemas"]["AIStatusResponse"];
        };
        /** CreateCase */
        CreateCase: {
            /** Symptom */
            symptom: string;
            /** Capture Name */
            capture_name?: string | null;
        };
        /** DeletionResponse */
        DeletionResponse: {
            /** Deleted */
            deleted: boolean;
            /** Original Deleted */
            original_deleted: boolean;
            /** Registered Artifacts Deleted */
            registered_artifacts_deleted: boolean;
            /** Cleanup Pending */
            cleanup_pending: boolean;
        };
        /** EvidenceCaptureProvenance */
        EvidenceCaptureProvenance: {
            /** Artifact Id */
            artifact_id: string;
            /** Parent Sha256 */
            parent_sha256: string;
            /** Case Id */
            case_id: string;
            /** Finding Id */
            finding_id: string;
            /** Related Finding Ids */
            related_finding_ids: string[];
            /** Evidence Ids */
            evidence_ids: string[];
            /** Extraction Mode */
            extraction_mode: string;
            /** Extraction Rule */
            extraction_rule: {
                [key: string]: unknown;
            };
            /** Display Filter */
            display_filter: string;
            /** Created */
            created: string;
            /** Tool Versions */
            tool_versions: {
                [key: string]: string;
            };
        };
        /** EvidenceCaptureRequest */
        EvidenceCaptureRequest: {
            /** Finding Id */
            finding_id: string;
        };
        /** EvidenceCaptureResponse */
        EvidenceCaptureResponse: {
            /** Artifact Id */
            artifact_id: string;
            /** Sha256 */
            sha256: string;
            /** Bytes */
            bytes: number;
            provenance: components["schemas"]["EvidenceCaptureProvenance"];
        };
        /** FollowupRequest */
        FollowupRequest: {
            /** Question */
            question: string;
        };
        /** FollowupResponse */
        FollowupResponse: {
            /** Answer */
            answer: string;
            /** Evidence Ids */
            evidence_ids: string[];
        };
        /** HTTPValidationError */
        HTTPValidationError: {
            /** Detail */
            detail?: components["schemas"]["ValidationError"][];
        };
        /** HealthResponse */
        HealthResponse: {
            /** Status */
            status: string;
            /** Gate */
            gate: number;
            /** Provider Mode */
            provider_mode: string;
            ai: components["schemas"]["AIStatusResponse"];
        };
        /** HistoryResponse */
        HistoryResponse: {
            /** Seq */
            seq: number;
            /** State */
            state: string;
            /** At */
            at: string;
        };
        /** RecentCaseResponse */
        RecentCaseResponse: {
            /** Id */
            id: string;
            /** Name */
            name: string;
            /** Capture Bytes */
            capture_bytes: number | null;
            /** Created */
            created: string;
            /** Updated */
            updated: string;
            /** State */
            state: string;
        };
        /** RenameCase */
        RenameCase: {
            /** Display Name */
            display_name: string;
        };
        /** RunResponse */
        RunResponse: {
            /** Id */
            id: string;
            /** Case Id */
            case_id: string;
            /** Request Key */
            request_key: string;
            /** Capability */
            capability: string;
            /** Parameters */
            parameters: {
                [key: string]: unknown;
            };
            /** Status */
            status: string;
            /** Error */
            error: string | null;
            /** Versions */
            versions: {
                [key: string]: unknown;
            } | null;
            /** Configuration */
            configuration: {
                [key: string]: unknown;
            } | null;
            /** Evidence Ids */
            evidence_ids: string[];
            /** Created */
            created: string;
        };
        /** ValidationError */
        ValidationError: {
            /** Location */
            loc: (string | number)[];
            /** Message */
            msg: string;
            /** Error Type */
            type: string;
            /** Input */
            input?: unknown;
            /** Context */
            ctx?: Record<string, never>;
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    health_api_health_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    capabilities_api_config_capabilities_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CapabilitiesResponse"];
                };
            };
        };
    };
    recent_cases_api_cases_get: {
        parameters: {
            query?: {
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecentCaseResponse"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_api_cases_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateCase"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_case_api_cases__case_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    delete_api_cases__case_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeletionResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    rename_case_api_cases__case_id__patch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RenameCase"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    capture_api_cases__case_id__capture_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/octet-stream": string;
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    investigate_api_cases__case_id__investigate_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    followup_api_cases__case_id__followups_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["FollowupRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FollowupResponse"];
                };
            };
            /** @description Code-only error: case_not_found, report_not_found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "case_not_found" | "report_not_found";
                        };
                    };
                };
            };
            /** @description Code-only error: report_not_ready, followup_unavailable */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "report_not_ready" | "followup_unavailable";
                        };
                    };
                };
            };
            /** @description Code-only error: request_size_limit */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "request_size_limit";
                        };
                    };
                };
            };
            /** @description Code-only error: invalid_request */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "invalid_request";
                        };
                    };
                };
            };
            /** @description Code-only error: followup_response_invalid */
            502: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "followup_response_invalid";
                        };
                    };
                };
            };
            /** @description Code-only error: provider_unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "provider_unavailable";
                        };
                    };
                };
            };
            /** @description Code-only error: provider_timeout */
            504: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            /** @enum {string} */
                            code: "provider_timeout";
                        };
                    };
                };
            };
            /** @description Code-only error */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        error: {
                            code: string;
                        };
                    };
                };
            };
        };
    };
    capability_api_cases__case_id__capabilities_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CapabilityRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    evidence_capture_api_cases__case_id__artifacts_evidence_capture_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EvidenceCaptureRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EvidenceCaptureResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    bridge_grant_api_cases__case_id__bridge_grants_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BridgeGrantRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BridgeGrantResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    evidence_api_cases__case_id__evidence_get: {
        parameters: {
            query?: {
                offset?: number;
                limit?: number;
            };
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    evidence_item_api_cases__case_id__evidence__evidence_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
                evidence_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    findings_api_cases__case_id__findings_get: {
        parameters: {
            query?: {
                offset?: number;
                limit?: number;
            };
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    report_api_cases__case_id__report_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    artifact_metadata_api_cases__case_id__artifacts__artifact_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
                artifact_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ArtifactResponse"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
}
