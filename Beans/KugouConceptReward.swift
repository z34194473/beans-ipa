import Foundation

/// 酷狗概念版每日 VIP 奖励（登录态操作，与取链通道无关）。
///
/// 接口与参数已实测（2026-11-20）：
/// - 全部 6 个接口在 appid=3116 / clientver=11440 / 不带 `srcappid` 的签名配方下通过服务端签名校验，
///   匿名或假 token 返回 `error_code=51002`；带 token 但签名错误返回 `20006 "err signature"`；
///   完全不带 token/userid 返回 `20002`。
/// - 因此本模块的所有失败都只可能是登录态或权益问题，不会静默吞掉签名错误。
///
/// 签名：`md5(signSecret + Σ排序k=v + body + signSecret)`，salt 是概念版 android 盐
/// `LnT6xpN3khm36zse0QzvmgTZ3waWdRSA`（与 `KugouConceptAPI` 同一套）。
final class KugouConceptReward {
    static let shared = KugouConceptReward()

    // MARK: - 常量

    private let gateway = "https://gateway.kugou.com"
    private let vipHost = "https://kugouvip.kugou.com"
    private let appid = "3116"
    private let clientver = "11440"
    private let signSecret = "LnT6xpN3khm36zse0QzvmgTZ3waWdRSA"
    private let ua = "Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi"
    private let listenUA = "Android13-1070-10566-201-0-ReportPlaySongToServerProtocol-wifi"
    /// 酷狗服务端只认这个来源；90139 也有人用，实测 90137 通过。
    private let claimSourceId = "90137"
    private let adId = "12307537187"
    private let adPlayMs: Int64 = 30_000

    /// 业务错误码
    enum RewardCode {
        static let notLoggedIn = 20_002      // 不带 token/userid
        static let badSignature = 20_006     // 签名校验失败（"err signature"）
        static let tokenInvalid = 51_002     // token 无效/过期
        static let alreadyClaimed = 130_012  // 今日已领取
        static let alreadyClaimedAlt = 131_001
        static let adExhausted = 30_002      // 今日广告次数用尽
        static let deviceRisk = 20_028       // 设备风控
    }

    struct Result {
        let ok: Bool
        let already: Bool
        let exhausted: Bool
        let code: Int
        let message: String
        let raw: [String: Any]

        static func failure(code: Int, message: String, raw: [String: Any] = [:]) -> Result {
            Result(ok: false, already: false, exhausted: false, code: code, message: message, raw: raw)
        }
    }

    private let defaultsKeyPrefix = "beans.kugou.reward."
    private var inFlightDaily = false

    // MARK: - 对外入口

    /// App 进入前台 / 启动时调用：每日领取 + 升级 + 广告奖励（每天各一次上限）。
    /// 失败只写日志，不影响播放。
    @discardableResult
    func autoRunDailyIfNeeded() async -> [String: Result] {
        guard KugouMusicAuth.shared.isLoggedIn else {
            BeansLogger.shared.log("酷狗概念版奖励：未登录酷狗，跳过", level: .debug)
            return [:]
        }
        if inFlightDaily { return [:] }
        inFlightDaily = true
        defer { inFlightDaily = false }

        var output: [String: Result] = [:]
        if !hasRunToday("claim") {
            let claim = await claimDailyVip()
            output["claim"] = claim
            if claim.ok || claim.already {
                markRunToday("claim")
            }
            if claim.code == RewardCode.badSignature || claim.code == RewardCode.notLoggedIn {
                // 签名或登录态层面的硬失败，后续接口也没必要继续打
                return output
            }
        }
        if !hasRunToday("upgrade") {
            let upgrade = await upgradeVip()
            output["upgrade"] = upgrade
            if upgrade.ok || upgrade.already { markRunToday("upgrade") }
        }
        if !hasRunToday("ad") {
            let ad = await reportAds(maxTimes: 8, intervalSeconds: 30)
            output["ad"] = ad
            if ad.ok || ad.already || ad.exhausted { markRunToday("ad") }
        }
        return output
    }

    /// 每日领取一天概念版 VIP。
    /// `POST /youth/v1/recharge/receive_vip_listen_song?source_id=90137&receive_day=yyyy-MM-dd`
    /// `receive_day` 必须是**北京时间**日期，不是 UTC。
    func claimDailyVip() async -> Result {
        await request(
            host: gateway,
            path: "/youth/v1/recharge/receive_vip_listen_song",
            method: "POST",
            params: ["source_id": claimSourceId, "receive_day": Self.beijingDayKey()],
            body: nil,
            ua: ua,
            task: "每日领取"
        )
    }

    /// 本月 VIP 领取记录，用来判断今天是否已经领过（比本地标记可靠）。
    /// `GET /youth/v1/activity/get_month_vip_record?latest_limit=31`
    func monthVipRecords(limit: Int = 31) async -> Result {
        await request(
            host: gateway,
            path: "/youth/v1/activity/get_month_vip_record",
            method: "GET",
            params: ["latest_limit": String(limit)],
            body: nil,
            ua: ua,
            task: "本月记录"
        )
    }

    /// 服务端侧「今天是否已领」。
    func hasClaimedTodayRemotely() async -> Bool? {
        let result = await monthVipRecords()
        guard result.ok else { return nil }
        let today = Self.beijingDayKey()
        let text = Self.flatten(result.raw)
        return text.contains("\"\(today)\"") || text.contains(today)
    }

    /// 升级概念版 VIP（广告奖励的升级位）。
    /// `POST /youth/v1/listen_song/upgrade_vip_reward?kugouid=<userid>&ad_type=1`
    func upgradeVip() async -> Result {
        let userId = KugouMusicAuth.shared.userId
        return await request(
            host: gateway,
            path: "/youth/v1/listen_song/upgrade_vip_reward",
            method: "POST",
            params: ["kugouid": userId.isEmpty ? "0" : userId, "ad_type": "1"],
            body: nil,
            ua: ua,
            task: "升级VIP"
        )
    }

    /// 上报一首自然播放完成的歌曲，用来领听歌奖励。
    /// `POST /youth/v2/report/listen_song?clientver=10566`，body `{"mixsongid":<数字>}`
    func reportListen(mixsongId: String) async -> Result {
        let trimmed = mixsongId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, Int64(trimmed) != nil else {
            return .failure(code: -1, message: "mixsongid 无效：\(mixsongId)")
        }
        // body 必须与签名时用的字符串逐字节一致
        let body = "{\"mixsongid\":\(trimmed)}"
        return await request(
            host: gateway,
            path: "/youth/v2/report/listen_song",
            method: "POST",
            params: ["clientver": "10566"],
            body: body,
            ua: listenUA,
            contentType: "application/json; charset=utf-8",
            task: "听歌奖励"
        )
    }

    /// 广告播放上报，最多 `maxTimes` 次，每次间隔 `intervalSeconds` 秒（服务端上限 8 次/天）。
    /// `POST /youth/v1/ad/play_report`，body `{"ad_id":…,"play_end":…,"play_start":…}`（毫秒）
    func reportAds(maxTimes: Int = 8, intervalSeconds: Int = 30) async -> Result {
        let total = max(1, min(maxTimes, 8))
        var completed = 0
        var last = Result.failure(code: 0, message: "未执行")
        for index in 1...total {
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let body = "{\"ad_id\":\(adId),\"play_end\":\(now),\"play_start\":\(now - adPlayMs)}"
            last = await request(
                host: gateway,
                path: "/youth/v1/ad/play_report",
                method: "POST",
                params: [:],
                body: body,
                ua: ua,
                contentType: "application/json; charset=utf-8",
                task: "广告奖励"
            )
            if last.exhausted {
                BeansLogger.shared.log("酷狗概念版广告奖励：今日次数已用尽（已完成 \(completed) 次）", level: .debug)
                return last
            }
            if !last.ok {
                BeansLogger.shared.log("酷狗概念版广告奖励：第 \(index) 次失败 code=\(last.code) \(last.message)", level: .debug)
                return last
            }
            completed += 1
            BeansLogger.shared.log("酷狗概念版广告奖励：第 \(completed)/\(total) 次成功", level: .debug)
            if index < total {
                try? await Task.sleep(nanoseconds: UInt64(intervalSeconds) * 1_000_000_000)
            }
        }
        return last
    }

    /// VIP 到期时间（概念版权益页）。参数不完整时返回 nil，不影响其它任务。
    func unionVipExpiry() async -> String? {
        let result = await request(
            host: vipHost,
            path: "/v1/get_union_vip",
            method: "GET",
            params: ["busi_type": "concept", "opt_product_types": "dvip,qvip",
                     "product_type": "svip"],
            body: nil,
            ua: ua,
            task: "VIP状态"
        )
        guard result.ok else { return nil }
        let expiry = Self.deepValue(result.raw, keys: ["vip_end_time", "end_time", "expire_time"])
        return expiry.map { String(describing: $0) }
    }

    // MARK: - 请求与签名

    private func request(
        host: String,
        path: String,
        method: String,
        params: [String: String],
        body: String?,
        ua: String,
        contentType: String = "application/json; charset=utf-8",
        task: String
    ) async -> Result {
        let auth = KugouMusicAuth.shared
        guard auth.isLoggedIn, !auth.token.isEmpty else {
            return .failure(code: RewardCode.notLoggedIn, message: "未登录酷狗")
        }
        // 设备 ID 缺失时先补注册，否则服务端按匿名处理
        var dfid = auth.dfid
        if dfid.isEmpty || dfid == "-" {
            dfid = await KugouConceptAPI.shared.ensureDFID()
        }
        let mid = auth.mid.isEmpty ? "-" : auth.mid
        let userId = auth.userId.isEmpty ? "0" : auth.userId

        // 正式参数集：不带 srcappid（带上会被判 err signature），uuid 固定 "-"
        var query: [String: String] = [
            "appid": appid,
            "clientver": clientver,
            "dfid": dfid,
            "mid": mid,
            "uuid": "-",
            "clienttime": "\(Int(Date().timeIntervalSince1970))",
            "token": auth.token,
            "userid": userId,
        ]
        for (key, value) in params { query[key] = value }

        // 签名：md5(secret + 排序 k=v 拼接 + body + secret)
        let canonical = query.keys.sorted().map { "\($0)=\(query[$0] ?? "")" }.joined()
        query["signature"] = Self.md5Hex(signSecret + canonical + (body ?? "") + signSecret)

        guard var comps = URLComponents(string: host + path) else {
            return .failure(code: -1, message: "URL 构造失败")
        }
        comps.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
        guard let url = comps.url else { return .failure(code: -1, message: "URL 构造失败") }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 20
        req.setValue(ua, forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue(
            "token=\(auth.token); userid=\(userId); dfid=\(dfid); KUGOU_API_MID=\(mid)",
            forHTTPHeaderField: "Cookie"
        )
        if let body {
            req.httpBody = Data(body.utf8)
            req.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }

        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
            let code = Self.intValue(json["error_code"]) ?? Self.intValue(json["errcode"]) ?? 0
            let status = Self.intValue(json["status"]) ?? 0
            let message = (json["error_msg"] as? String).flatMap { $0.isEmpty ? nil : $0 }
                ?? (json["msg"] as? String)
                ?? (json["message"] as? String)
                ?? ""

            if code == RewardCode.alreadyClaimed || code == RewardCode.alreadyClaimedAlt {
                BeansLogger.shared.log("酷狗概念版\(task)：今日已领取", level: .debug)
                return Result(ok: true, already: true, exhausted: false, code: code, message: "今日已领取", raw: json)
            }
            if code == RewardCode.adExhausted {
                return Result(ok: false, already: false, exhausted: true, code: code, message: "今日次数已用尽", raw: json)
            }
            if code == 0 && (status == 1 || status == 0) {
                BeansLogger.shared.log("酷狗概念版\(task)：成功", level: .debug)
                return Result(ok: true, already: false, exhausted: false, code: 0, message: message.isEmpty ? "成功" : message, raw: json)
            }
            let reason: String
            switch code {
            case RewardCode.badSignature: reason = "签名校验失败"
            case RewardCode.notLoggedIn: reason = "登录态缺失"
            case RewardCode.tokenInvalid: reason = "token 失效，请重新扫码登录酷狗"
            case RewardCode.deviceRisk: reason = "设备风控，需重新注册设备 dfid"
            default: reason = message.isEmpty ? "接口返回 \(code)" : message
            }
            BeansLogger.shared.log("酷狗概念版\(task)：失败 code=\(code) \(reason)", level: .debug)
            return Result(ok: false, already: false, exhausted: false, code: code, message: reason, raw: json)
        } catch {
            BeansLogger.shared.log("酷狗概念版\(task)：网络错误 \(error.localizedDescription)", level: .debug)
            return .failure(code: -1, message: error.localizedDescription)
        }
    }

    // MARK: - 工具

    /// 北京时间 yyyy-MM-dd；`receive_day` 必须用它，用 UTC 会跨日失败。
    static func beijingDayKey(_ date: Date = Date()) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "Asia/Shanghai") ?? .current
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 1970, parts.month ?? 1, parts.day ?? 1)
    }

    static func md5Hex(_ text: String) -> String {
        let data = Data(text.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_MD5(buffer.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func intValue(_ value: Any?) -> Int? {
        if let number = value as? Int { return number }
        if let number = value as? NSNumber { return number.intValue }
        if let text = value as? String { return Int(text) }
        return nil
    }

    private static func flatten(_ value: Any) -> String {
        if let data = try? JSONSerialization.data(withJSONObject: value),
           let text = String(data: data, encoding: .utf8) {
            return text
        }
        return ""
    }

    private static func deepValue(_ json: [String: Any], keys: [String]) -> Any? {
        for key in keys where json[key] != nil { return json[key] }
        for (_, value) in json {
            if let dict = value as? [String: Any], let found = deepValue(dict, keys: keys) { return found }
            if let array = value as? [Any] {
                for item in array {
                    if let dict = item as? [String: Any], let found = deepValue(dict, keys: keys) { return found }
                }
            }
        }
        return nil
    }

    // MARK: - 本地每日标记（避免同一自然日重复打接口）

    private func hasRunToday(_ key: String) -> Bool {
        UserDefaults.standard.string(forKey: defaultsKeyPrefix + key) == Self.beijingDayKey()
    }

    private func markRunToday(_ key: String) {
        UserDefaults.standard.set(Self.beijingDayKey(), forKey: defaultsKeyPrefix + key)
    }
}
