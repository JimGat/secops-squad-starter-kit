// KQL operator, function, and table reference data.
// Offline reference — no Azure connectivity required.

'use strict';

/**
 * Valid KQL tabular operators.
 * Used in pipe-delimited statements: `| operator ...`
 * @type {ReadonlySet<string>}
 */
const OPERATORS = new Set([
  'where',
  'summarize',
  'extend',
  'project',
  'project-away',
  'project-keep',
  'project-rename',
  'project-reorder',
  'join',
  'union',
  'let',
  'print',
  'render',
  'sort',
  'order',
  'top',
  'top-nested',
  'count',
  'distinct',
  'take',
  'limit',
  'search',
  'find',
  'mv-expand',
  'mv-apply',
  'parse',
  'parse-where',
  'parse-kv',
  'evaluate',
  'make-series',
  'invoke',
  'external_data',
  'externaldata',
  'getschema',
  'facet',
  'as',
  'consume',
  'lookup',
  'datatable',
  'range',
  'sample',
  'sample-distinct',
  'serialize',
  'fork',
  'partition',
  'scan',
  'assert',
]);

/**
 * Common KQL scalar, aggregation, and window functions.
 * @type {ReadonlySet<string>}
 */
const FUNCTIONS = new Set([
  // Datetime
  'ago', 'now', 'datetime', 'timespan', 'todatetime', 'totimespan',
  'datetime_add', 'datetime_diff', 'datetime_part', 'dayofweek', 'dayofmonth',
  'dayofyear', 'monthofyear', 'weekofyear', 'hourofday', 'startofday',
  'startofweek', 'startofmonth', 'startofyear', 'endofday', 'endofweek',
  'endofmonth', 'endofyear', 'format_datetime', 'format_timespan',
  'make_datetime', 'make_timespan', 'unixtime_seconds_todatetime',
  'unixtime_milliseconds_todatetime', 'unixtime_microseconds_todatetime',
  'unixtime_nanoseconds_todatetime',
  // Type conversion
  'todynamic', 'tostring', 'toint', 'tolong', 'todouble', 'toreal',
  'tobool', 'todecimal', 'toguid', 'tohex',
  // String
  'strlen', 'substring', 'trim', 'trim_start', 'trim_end', 'split',
  'strcat', 'strcat_delim', 'replace_string', 'replace_regex',
  'reverse', 'toupper', 'tolower', 'indexof', 'indexof_regex',
  'countof', 'extract', 'extract_all', 'parse_json', 'parse_url',
  'parse_urlquery', 'parse_path', 'parse_version', 'parse_ipv4',
  'parse_ipv6', 'parse_csv', 'parse_xml', 'parse_command_line',
  'translate', 'url_decode', 'url_encode',
  'base64_encode_tostring', 'base64_decode_tostring',
  // String predicates (used in where clauses)
  'has', 'has_cs', 'has_any', 'has_all', 'contains', 'contains_cs',
  'startswith', 'startswith_cs', 'endswith', 'endswith_cs',
  'matches', 'isempty', 'isnotempty', 'isnull', 'isnotnull',
  'isnan', 'isinf', 'isfinite',
  // Conditional
  'iff', 'iif', 'case', 'coalesce', 'max_of', 'min_of',
  // Math
  'bin', 'floor', 'ceiling', 'round', 'abs', 'sign', 'pow',
  'sqrt', 'log', 'log2', 'log10', 'exp', 'exp2', 'exp10',
  'pi', 'rand', 'beta_cdf', 'beta_inv', 'beta_pdf',
  // Aggregation
  'min', 'max', 'sum', 'avg', 'count', 'countif', 'dcount',
  'dcountif', 'percentile', 'percentiles', 'percentile_array',
  'stdev', 'stdevif', 'variance', 'varianceif',
  'arg_min', 'arg_max', 'any', 'anyif',
  'make_list', 'make_list_if', 'make_set', 'make_set_if',
  'make_bag', 'make_bag_if',
  'hll', 'hll_merge', 'dcount_hll', 'tdigest', 'tdigest_merge',
  'merge_tdigest', 'percentile_tdigest',
  'binary_all_and', 'binary_all_or', 'binary_all_xor',
  'buildschema', 'count_distinct',
  // Dynamic / JSON
  'pack', 'bag_pack', 'pack_array', 'pack_dictionary',
  'bag_keys', 'bag_values', 'bag_has_key', 'bag_merge', 'bag_remove_keys',
  'array_length', 'array_concat', 'array_index_of', 'array_slice',
  'array_sort_asc', 'array_sort_desc', 'array_split', 'array_sum',
  'array_reverse', 'array_rotate_left', 'array_rotate_right',
  'array_shift_left', 'array_shift_right', 'set_union', 'set_intersect',
  'set_difference', 'set_has_element', 'jaccard_index',
  'zip', 'repeat',
  'toscalar',
  // Hash / encoding
  'hash', 'hash_md5', 'hash_sha1', 'hash_sha256', 'hash_xxhash64',
  // IP
  'ipv4_is_match', 'ipv4_is_private', 'ipv4_is_in_range', 'ipv4_netmask_suffix',
  'ipv4_compare', 'ipv6_compare', 'ipv6_is_match', 'format_ipv4',
  'format_ipv4_mask', 'parse_ipv4_mask',
  // Geo
  'geo_point_to_s2cell', 'geo_point_to_geohash', 'geo_point_to_h3cell',
  'geo_distance_2points', 'geo_point_in_circle', 'geo_point_in_polygon',
  // Special
  'ingestion_time', 'cursor_after', 'current_principal',
  'current_principal_details', 'activity_counts_metrics',
  'new_activity_metrics', 'active_users_count',
  // Window functions
  'row_number', 'row_cumsum', 'row_rank', 'row_window_session',
  'prev', 'next', 'materialize',
  // Series
  'series_fill_const', 'series_fill_forward', 'series_fill_backward',
  'series_fill_linear', 'series_fir', 'series_iir', 'series_fit_line',
  'series_fit_2lines', 'series_fit_poly', 'series_outliers',
  'series_periods_detect', 'series_periods_validate', 'series_stats',
  'series_stats_dynamic', 'series_decompose', 'series_decompose_anomalies',
  'series_decompose_forecast', 'series_seasonal', 'series_greater',
  'series_less', 'series_equals', 'series_not_equals',
  'series_add', 'series_subtract', 'series_multiply', 'series_divide',
]);

/**
 * Common Microsoft Sentinel / Defender table names.
 * Used for "did you mean?" suggestions — not enforced as mandatory.
 * @type {ReadonlySet<string>}
 */
const TABLE_NAMES = new Set([
  // Sentinel core
  'SecurityEvent',
  'SecurityAlert',
  'SecurityIncident',
  // Entra ID / Azure AD
  'SignInLogs',
  'AuditLogs',
  'AADNonInteractiveUserSignInLogs',
  'AADManagedIdentitySignInLogs',
  'AADServicePrincipalSignInLogs',
  'AADProvisioningLogs',
  // Defender for Endpoint (MDE)
  'DeviceProcessEvents',
  'DeviceNetworkEvents',
  'DeviceFileEvents',
  'DeviceLogonEvents',
  'DeviceRegistryEvents',
  'DeviceImageLoadEvents',
  'DeviceEvents',
  'DeviceInfo',
  'DeviceNetworkInfo',
  'DeviceFileCertificateInfo',
  'DeviceTvmSoftwareInventory',
  'DeviceTvmSoftwareVulnerabilities',
  // Defender for Office 365
  'EmailEvents',
  'EmailAttachmentInfo',
  'EmailUrlInfo',
  'EmailPostDeliveryEvents',
  // Defender for Identity
  'IdentityLogonEvents',
  'IdentityQueryEvents',
  'IdentityDirectoryEvents',
  // Defender XDR
  'AlertEvidence',
  'AlertInfo',
  'CloudAppEvents',
  // Common data connectors
  'CommonSecurityLog',
  'Syslog',
  'AzureActivity',
  'AzureDiagnostics',
  'AzureMetrics',
  'Heartbeat',
  'ThreatIntelligenceIndicator',
  'BehaviorAnalytics',
  'Anomalies',
  'OfficeActivity',
  'W3CIISLog',
  // Watchlists and custom
  '_GetWatchlist',
  'Watchlist',
  'Usage',
  'Operation',
]);

module.exports = { OPERATORS, FUNCTIONS, TABLE_NAMES };
