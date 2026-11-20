import Foundation
import Security

/// 酷狗概念版（Kugou Concept，appid 3116 / clientver 11440）独立通道。
///
/// 为什么单独一个文件：
/// - `KugouMusicAPI.swift` 里的 `songURL(...)` 走的是「酷狗音乐」标准客户端 profile
///   （appid 1005 / clientver 20489 / pid 2 / page_id 151369488），对会员曲目经常只回
///   `status` 不回 `play_url`；
/// - 概念版通道用 appid 3116 / pid 411 / page_id 967177915 / version 11436，签名盐也换成
///   概念版专属的 `185672dd44712f60bb1736df5a377e82`，命中率更高；
/// - 概念版要求「先注册设备再取链」，`dfid` 必须是真值（默认 "-" 会被判 20028）。
///
/// 已实测（2026-11-20，Python 复刻同一套签名）：
/// - 搜索 `songsearch.kugou.com/song_search_v2`：匿名可用，返回 hash / album_id / hq_hash / sq_hash / res_hash；
/// - `gateway.kugou.com/v3/album_audio/audio`：匿名可用，换到 album_audio_id / audio_id（v5/url 需要）；
/// - `userservice.kugou.com/risk/v2/r_register_dev`：**body 必须是 AES 密文的 base64 字符串 +
///   Content-Type: text/plain;charset=UTF-8**，返回原始密文，解密后得 `{"status":1,"data":{"dfid":"..."}}`；
///   用原始密文字节 + application/octet-stream 会被回 `{"data":null,"status":0,"error_code":20006}`；
/// - `gateway.kugou.com/v5/url`：未登录一律 `{"status":2}`（鉴权层拒绝），必须带登录 token。
final class KugouConceptAPI {
    static let shared = KugouConceptAPI()

    // MARK: - 概念版常量

    private let gateway = "https://gateway.kugou.com"
    private let userService = "https://userservice.kugou.com"

    /// 概念版 appid（注意不是 1005）
    private let appid = "3116"
    /// 概念版 clientver
    private let clientver = "11440"
    /// 扫码登录用的 srcappid
    private let srcAppid = "2919"
    /// 概念版 UA（版本段 11083 也是特征之一）
    private let ua = "Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi"
    private let kgThash = "5d816a0"
    private let kgRf = "B9EDA08A64250DEFFBCADDEE00F8F25F"
    /// 概念版 android 签名盐：signature = md5(secret + 排序后的 k=v 拼接 + body + secret)
    private let signSecret = "LnT6xpN3khm36zse0QzvmgTZ3waWdRSA"
    /// 概念版取链盐：key = md5(hash + secret + appid + mid + userid)
    private let playSecret = "185672dd44712f60bb1736df5a377e82"
    /// v5/url 的页面埋点参数，概念版是 967177915
    private let pageId = "967177915"
    private let pPageId = "356753938,823673182,967485191"
    /// v5/url 的 pid，概念版是 411（标准版是 2）
    private let pid = "411"
    /// v5/url 的 version，概念版是 11436
    private let playVersion = "11436"
    /// 设备注册的 RSA 1024bit 公钥（与 KugouMusicAPI 内一致）
    private let rsaPublicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDECi0Np2UR87scwrvTr72L6oO01rBbbBPriSDFPxr3Z5syug0O24QyQO8bg27+0+4kBzTBTBOZ/WWU0WryL1JSXRTXLgFVxtzIY41Pe7lPOgsfTCn5kZcvKhYKJesKnnJDNr5/abvTGf+rHG3YRwsCHcQ08/q6ifSioBszvb3QiwIDAQAB"

    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 15
        config.httpShouldSetCookies = false
        session = URLSession(configuration: config)
    }

    struct ConceptPlayback {
        let url: String?
        let status: Int
        let code: Int
        let raw: [String: Any]
    }

    // MARK: - 设备注册（拿真 dfid）

    /// 概念版必须先注册设备。`dfid` 为 "-"、空、或长度不足时触发注册。
    @discardableResult
    func ensureDFID(force: Bool = false) async -> String {
        let auth = KugouMusicAuth.shared
        let current = auth.dfid
        if !force, current != "-", current.count >= 8 { return current }
        if let fresh = await registerDevice() { return fresh }
        return current
    }

    /// 复刻 `userservice.kugou.com/risk/v2/r_register_dev`。
    /// 请求：AES-CBC(明文=设备 JSON, key/iv=md5(随机6位).lower 的前/后 16 位) → base64 作为 body；
    ///      p = RSA_PKCS1v15({"aes": 随机6位, "uid": userid, "token": token}) 的 HEX；
    /// 响应：原始密文字节，用同一个 aes 口令解密。
    @discardableResult
    func registerDevice() async -> String? {
        let auth = KugouMusicAuth.shared
        let guid = auth.guid.isEmpty ? UUID().uuidString : auth.guid
        let deviceJSON: [String: Any] = [
            "availableRamSize": 4_983_533_568,
            "availableRomSize": 48_114_719,
            "availableSDSize": 48_114_717,
            "basebandVer": "",
            "batteryLevel": 100,
            "batteryStatus": 3,
            "brand": "Redmi",
            "buildSerial": "unknown",
            "device": "marble",
            "imei": guid,
            "imsi": "",
            "manufacturer": "Xiaomi",
            "uuid": guid,
            "accelerometer": false,
            "gravity": false,
            "gyroscope": false,
            "light": false,
            "magnetic": false,
            "orientation": false,
            "pressure": false,
            "step_counter": false,
            "temperature": false,
        ]
        guard let signatureSource = try? JSONSerialization.data(withJSONObject: deviceJSON, options: []),
              let aesKey = Self.randomAlpha(6)?.lowercased(),
              let cipher = Self.aesCBCEncrypt(signatureSource, password: aesKey) else { return nil }
        // 实测：这里必须是 base64 字符串；发原始密文字节会被服务端判 20006。
        let bodyString = cipher.base64EncodedString()
        guard let pPlain = try? JSONSerialization.data(withJSONObject: [
            "aes": aesKey,
            "uid": Int(auth.userId) ?? 0,
            "token": auth.token,
        ]),
              let rsa = Self.rsaEncryptPKCS1(pPlain, publicKeyBase64: rsaPublicKeyBase64) else { return nil }

        var params: [String: String] = [
            "dfid": "-",
            "mid": auth.mid,
            "uuid": "-",
            "appid": appid,
            "clientver": clientver,
            "clienttime": "\(Int(Date().timeIntervalSince1970))",
            "part": "1",
            "platid": "1",
            "p": rsa.hexString,
        ]
        if !auth.token.isEmpty { params["token"] = auth.token }
        if !auth.userId.isEmpty { params["userid"] = auth.userId }
        // 注册接口本身也要签名（body 参与 md5）
        params["signature"] = androidSignature(params: params, body: bodyString)

        guard var comps = URLComponents(string: userService + "/risk/v2/r_register_dev") else { return nil }
        comps.queryItems = params.map { URLQueryItem(name: $0.key, value: $0.value) }
        guard let url = comps.url else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = Data(bodyString.utf8)
        request.setValue("text/plain;charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue(ua, forHTTPHeaderField: "User-Agent")
        request.setValue("1", forHTTPHeaderField: "kg-rc")
        request.setValue(kgThash, forHTTPHeaderField: "kg-thash")
        request.setValue("1", forHTTPHeaderField: "kg-rec")
        request.setValue(kgRf, forHTTPHeaderField: "kg-rf")
        request.setValue("userservice.kugou.com", forHTTPHeaderField: "x-router")

        do {
            let (data, response) = try await session.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
            var json: [String: Any] = [:]
            if let plain = Self.aesCBCDecrypt(data, password: aesKey),
               let parsed = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] {
                json = parsed
            } else if let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                json = parsed
            }
            let dfid = Self.deepString(json, names: ["dfid"])
                ?? Self.deepString(json["data"] as? [String: Any] ?? [:], names: ["dfid"])
                ?? ""
            guard !dfid.isEmpty else {
                BeansLogger.shared.log("酷狗概念版设备注册未返回 dfid：\(Self.describe(json))", level: .debug)
                return nil
            }
            KugouMusicAuth.shared.saveDeviceDFID(dfid)
            BeansLogger.shared.log("酷狗概念版设备注册成功：dfid=\(dfid.prefix(6))… status=\(Self.deepInt(json, names: ["status"]))", level: .debug)
            return dfid
        } catch {
            BeansLogger.shared.log("酷狗概念版设备注册失败：\(error.localizedDescription)", level: .debug)
            return nil
        }
    }

    // MARK: - 概念版 Cookie

    /// 概念版 Cookie 比标准版多 KUGOU_API_GUID / DEV / MAC，缺 device 三元组时取链会被风控。
    func conceptCookie() -> String {
        let auth = KugouMusicAuth.shared
        var items: [(String, String)] = [
            ("userid", auth.userId),
            ("token", auth.token),
            ("t1", auth.t1),
            ("vip_token", auth.vipToken),
            ("dfid", auth.dfid),
            ("KUGOU_API_MID", auth.mid),
            ("KUGOU_API_GUID", auth.guid),
            ("KUGOU_API_DEV", auth.dev),
            ("KUGOU_API_MAC", auth.mac),
        ]
        if auth.vipType > 0 {
            items.append(("vip_type", "\(auth.vipType)"))
            items.append(("vipType", "\(auth.vipType)"))
        }
        return items.filter { !$0.1.isEmpty && $0.1 != "-" }.map { "\($0.0)=\($0.1)" }.joined(separator: "; ")
    }

    // MARK: - 取播放地址

    /// 概念版 v5/url。`album_audio_id` 建议先由 `trackInfo(hash:)` 拿到，缺省也能取链但命中率低。
    func songURL(
        hash: String,
        albumId: String?,
        albumAudioId: String?,
        quality: BeansAudioQuality
    ) async -> String? {
        let auth = KugouMusicAuth.shared
        let fileHash = hash.lowercased()
        // 概念版强制要求设备已注册
        let dfid = await ensureDFID()
        guard !dfid.isEmpty else { return nil }

        var verifiedAlbumAudioId = albumAudioId
        if verifiedAlbumAudioId?.isEmpty ?? true {
            verifiedAlbumAudioId = await trackInfo(hash: fileHash)?["album_audio_id"] as? String
        }

        // 概念版对同一首歌的可用品质不一致，按从高到低逐档试。
        for code in qualityCodes(for: quality) {
            let result = await requestPlayURL(
                hash: fileHash,
                albumId: albumId,
                albumAudioId: verifiedAlbumAudioId,
                qualityCode: code
            )
            if let url = result.url, !url.isEmpty {
                BeansLogger.shared.log("酷狗概念版命中：hash=\(fileHash.prefix(8)) quality=\(code)", level: .debug)
                return url
            }
            if result.code == 20_028 {
                // 设备校验失败：重新注册一次再试
                BeansLogger.shared.log("酷狗概念版设备校验失败(20028)，重新注册设备", level: .debug)
                _ = await registerDevice()
                let retry = await requestPlayURL(
                    hash: fileHash,
                    albumId: albumId,
                    albumAudioId: verifiedAlbumAudioId,
                    qualityCode: code
                )
                if let url = retry.url, !url.isEmpty { return url }
            }
        }
        BeansLogger.shared.log("酷狗概念版无地址：hash=\(fileHash.prefix(8)) 已登录=\(auth.isLoggedIn ? "是" : "否") token=\(auth.token.isEmpty ? "无" : "有") dfid=\(dfid.prefix(6))", level: .debug)
        return nil
    }

    func requestPlayURL(
        hash: String,
        albumId: String?,
        albumAudioId: String?,
        qualityCode: String
    ) async -> ConceptPlayback {
        let auth = KugouMusicAuth.shared
        let userId = auth.userId.isEmpty ? "0" : auth.userId
        var params: [String: String] = [
            "album_id": albumId ?? "0",
            "area_code": "1",
            "hash": hash,
            "ssa_flag": "is_fromtrack",
            "version": playVersion,
            "quality": qualityCode,
            "behavior": "play",
            "pid": pid,
            "cmd": "26",
            "pidversion": "3001",
            "page_id": pageId,
            "ppage_id": pPageId,
            "IsFreePart": auth.vipType > 0 ? "0" : "1",
            "cdnBackup": "1",
            "kcard": "0",
            "module": "",
            "appid": appid,
            "clientver": clientver,
            "mid": auth.mid,
            "dfid": auth.dfid,
            "userid": userId,
            "token": auth.token.isEmpty ? "0" : auth.token,
            "clienttime": "\(Int(Date().timeIntervalSince1970))",
        ]
        // album_audio_id 参与签名，必须放在算 key / signature 之前
        params["album_audio_id"] = (albumAudioId?.isEmpty == false) ? (albumAudioId ?? "0") : "0"
        // key = md5(hash + playSecret + appid + mid + userid)，注意这里是概念版盐
        params["key"] = Self.md5Hex(hash + playSecret + appid + auth.mid + userId)
        // 概念版取链也带 android 签名（body 为空串）
        params["signature"] = androidSignature(params: params, body: "")

        guard var comps = URLComponents(string: gateway + "/v5/url") else {
            return ConceptPlayback(url: nil, status: 0, code: -1, raw: [:])
        }
        comps.queryItems = params.map { URLQueryItem(name: $0.key, value: $0.value) }
        guard let url = comps.url else { return ConceptPlayback(url: nil, status: 0, code: -1, raw: [:]) }
        var request = URLRequest(url: url)
        request.setValue(ua, forHTTPHeaderField: "User-Agent")
        request.setValue("trackercdn.kugou.com", forHTTPHeaderField: "x-router")
        request.setValue("1", forHTTPHeaderField: "kg-rc")
        request.setValue(kgThash, forHTTPHeaderField: "kg-thash")
        request.setValue("1", forHTTPHeaderField: "kg-rec")
        request.setValue(kgRf, forHTTPHeaderField: "kg-rf")
        request.setValue(auth.dfid, forHTTPHeaderField: "dfid")
        request.setValue(auth.mid, forHTTPHeaderField: "mid")
        request.setValue(conceptCookie(), forHTTPHeaderField: "Cookie")

        do {
            let (data, response) = try await session.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                return ConceptPlayback(url: nil, status: 0, code: -1, raw: [:])
            }
            let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
            // 概念版 v5/url 成功时 url 是「字符串数组」，失败时是 status=2 / errcode=20028
            return ConceptPlayback(
                url: Self.firstURL(in: json),
                status: Self.deepInt(json, names: ["status"]),
                code: Self.deepInt(json, names: ["errcode", "error_code", "err_code", "code"]),
                raw: json
            )
        } catch {
            BeansLogger.shared.log("酷狗概念版 v5/url 请求失败：\(error.localizedDescription)", level: .debug)
            return ConceptPlayback(url: nil, status: 0, code: -1, raw: [:])
        }
    }

    // MARK: - 曲目信息（换 album_audio_id）

    /// `gateway.kugou.com/v3/album_audio/audio`：匿名可用，返回 album_audio_id / audio_id /
    /// hq_hash / sq_hash / res_hash。v5/url 带上 album_audio_id 命中率明显更高。
    func trackInfo(hash: String) async -> [String: Any]? {
        let auth = KugouMusicAuth.shared
        var params: [String: String] = [
            "appid": "1005",
            "clientver": "11451",
            "clienttime": "\(Int(Date().timeIntervalSince1970))",
            "mid": auth.mid,
            "dfid": auth.dfid,
        ]
        if !auth.userId.isEmpty { params["userid"] = auth.userId }
        if !auth.token.isEmpty { params["token"] = auth.token }
        let payload: [String: Any] = ["data": [["hash": hash.uppercased()]]]
        guard let body = try? JSONSerialization.data(withJSONObject: payload) else { return nil }
        var comps = URLComponents(string: gateway + "/v3/album_audio/audio")
        comps?.queryItems = params.map { URLQueryItem(name: $0.key, value: $0.value) }
        guard let url = comps?.url else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(ua, forHTTPHeaderField: "User-Agent")
        request.setValue("kmr.service.kugou.com", forHTTPHeaderField: "x-router")
        request.setValue(kgThash, forHTTPHeaderField: "kg-thash")
        request.setValue(kgRf, forHTTPHeaderField: "kg-rf")
        request.setValue(auth.dfid, forHTTPHeaderField: "dfid")
        request.setValue(auth.mid, forHTTPHeaderField: "mid")
        guard let (data, response) = try? await session.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        // 上游把数组放在 data / data.info / info 里，逐个探测
        if let array = json["data"] as? [[String: Any]], let first = array.first { return first }
        if let data = json["data"] as? [String: Any] {
            for key in ["info", "lists", "list", "audio_info"] {
                if let array = data[key] as? [[String: Any]], let first = array.first { return first }
            }
        }
        if let array = json["info"] as? [[String: Any]], let first = array.first { return first }
        return nil
    }

    // MARK: - 签名 / 加密

    /// 概念版 android 签名：md5(secret + Σ排序后 k=v + body + secret)
    func androidSignature(params: [String: String], body: String) -> String {
        let joined = params.keys.sorted().map { "\($0)=\(params[$0] ?? "")" }.joined()
        return Self.md5Hex(signSecret + joined + body + signSecret)
    }

    private func qualityCodes(for quality: BeansAudioQuality) -> [String] {
        switch quality {
        case .standard:
            return ["128", "320", "flac"]
        case .higher:
            return ["320", "128", "flac"]
        case .exhigh:
            return ["320", "flac", "128"]
        case .lossless:
            return ["flac", "320", "128"]
        case .hires:
            return ["high", "flac", "320", "128"]
        }
    }

    // MARK: - 基础工具（与 KugouMusicAPI 内部实现保持一致）

    private static func md5Hex(_ text: String) -> String {
        Data(text.utf8).md5Hex()
    }

    private static func randomAlpha(_ length: Int) -> String? {
        let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return String((0..<length).map { _ in chars[Int.random(in: 0..<chars.count)] })
    }

    private static func aesCBCEncrypt(_ data: Data, password: String) -> Data? {
        let digest = md5Hex(password)
        return crypt(data, operation: CCOperation(kCCEncrypt), key: Data(digest.prefix(16).utf8), iv: Data(digest.suffix(16).utf8))
    }

    private static func aesCBCDecrypt(_ data: Data, password: String) -> Data? {
        let digest = md5Hex(password)
        return crypt(data, operation: CCOperation(kCCDecrypt), key: Data(digest.prefix(16).utf8), iv: Data(digest.suffix(16).utf8))
    }

    private static func crypt(_ data: Data, operation: CCOperation, key: Data, iv: Data) -> Data? {
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let capacity = out.count
        var outLength = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { dataPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, kCCKeySizeAES128,
                            ivPtr.baseAddress,
                            dataPtr.baseAddress, data.count,
                            outPtr.baseAddress, capacity,
                            &outLength
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        out.removeSubrange(outLength..<capacity)
        return out
    }

    private static func rsaEncryptPKCS1(_ data: Data, publicKeyBase64: String) -> Data? {
        guard let keyData = Data(base64Encoded: publicKeyBase64) else { return nil }
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 1024,
        ]
        guard let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, nil) else { return nil }
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, data as CFData, &error) else { return nil }
        return encrypted as Data
    }

    private static func firstURL(in json: [String: Any]) -> String? {
        for key in ["url", "play_url", "play_backup_url", "backup_url", "src"] {
            if let value = json[key] as? String, !value.isEmpty { return value }
            if let array = json[key] as? [String], let first = array.first, !first.isEmpty { return first }
            if let array = json[key] as? [[String: Any]], let first = array.first,
               let nested = firstURL(in: first) { return nested }
        }
        return nil
    }

    private static func deepString(_ json: [String: Any], names: [String]) -> String? {
        for name in names {
            if let value = json[name] as? String, !value.isEmpty { return value }
            if let value = json[name] as? NSNumber { return value.stringValue }
        }
        for value in json.values {
            if let nested = value as? [String: Any], let found = deepString(nested, names: names) { return found }
            if let array = value as? [[String: Any]] {
                for item in array {
                    if let found = deepString(item, names: names) { return found }
                }
            }
        }
        return nil
    }

    private static func deepInt(_ json: [String: Any], names: [String]) -> Int {
        for name in names {
            if let value = json[name] as? Int { return value }
            if let value = json[name] as? NSNumber { return value.intValue }
            if let value = json[name] as? String, let parsed = Int(value) { return parsed }
        }
        return 0
    }

    private static func describe(_ json: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: json),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return String(text.prefix(200))
    }
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
