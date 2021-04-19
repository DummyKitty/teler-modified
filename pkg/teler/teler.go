package teler

import (
	"io/ioutil"
	"ktbs.dev/teler/internal/libinjection"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/satyrius/gonx"
	"github.com/valyala/fastjson"
	"ktbs.dev/teler/common"
	"ktbs.dev/teler/pkg/matchers"
	"ktbs.dev/teler/pkg/metrics"
	"ktbs.dev/teler/pkg/requests"
	"ktbs.dev/teler/resource"
)

func Libinjection_judge(s string)(bool,string,string){
	s = "http://www.test.com/?" + s
	req, err := url.ParseRequestURI(s)
	if err != nil{
		found, fingerprint := libinjection.IsSQLi(s)
		if found {
			return found, fingerprint,"sql injection"
		}

		found, fingerprint = libinjection.IsXSS(s)
		if found {
			return found, fingerprint,"XSS"
		}
		return false,"",""
	}

	query := req.Query()
	for _,q := range query {
		qs := strings.Join(q, "")
		found, fingerprint := libinjection.IsSQLi(qs)
		if found {
			return found, fingerprint,"sql injection"
		}

		found, fingerprint = libinjection.IsXSS(qs)
		if found {
			return found, fingerprint,"XSS"
		}
	}
	return false,"",""
}


func ml_analysis(s string)(bool,string){
	req,err := http.NewRequest("GET","http://python:64290"+s,nil)
	client := requests.Client()

	if err != nil {
		return false,""
	}
	res, err := client.Do(req)
	if err != nil {
		return false,""
	}
	content, errCon := ioutil.ReadAll(res.Body)
	if errCon != nil {
		return false,""
	}

	v,_ := fastjson.Parse(string(content))
	message:=string(v.GetStringBytes("message"))
	if (message == "MALICIOUS"){
		return true,"机器学习引擎检测到攻击"
	}else {
		return false,""
	}

}

// Analyze logs from threat resources
func Analyze(options *common.Options, logs *gonx.Entry) (bool, map[string]string) {
	var match, status bool

	log := make(map[string]string)

	// mainMapB := make(map[string]map[string]string)

	// 初始化字典
	rsc := resource.Get()
	// rsc存放着teler_resource中的内容
	fields := reflect.ValueOf(logs).Elem().FieldByName("fields")
	//
	for _, field := range fields.MapKeys() {
		log[field.String()] = fields.MapIndex(field).String()
	}

	log["Bad Crawler"] = "False"
	log["Bad IP"] = "False"
	log["Bad Referrer"] = "False"
	log["category"] = "None"
	log["description"] = ""

	for i := 0; i < len(rsc.Threat); i++ {
		threat := reflect.ValueOf(&rsc.Threat[i]).Elem()
		cat := threat.FieldByName("Category").String()
		con := threat.FieldByName("Content").String()
		exc := threat.FieldByName("Exclude").Bool()

		if exc {
			continue
		}
		// 匹配部分
		switch cat {
		case "Common Web Attack":
			req, err := url.ParseRequestURI(log["request_uri"])
			if err != nil {
				break
			}

			query := req.Query()
			if len(query) > 0 {
				for p, q := range query {
					dec, err := url.QueryUnescape(strings.Join(q, ""))
					if err != nil {
						continue
					}

					if isWhitelist(options, p+"="+dec) {
						continue
					}

					cwa, _ := fastjson.Parse(con)
					for _, v := range cwa.GetArray("filters") {

						//log["category"] = cat + ": " + string(v.GetStringBytes("description"))
						quote := regexp.QuoteMeta(dec)

						match_web := matchers.IsMatch(
							string(v.GetStringBytes("rule")),
							quote,
						)

						if match_web {
							log["category"] = cat
							log["description"] = string(v.GetStringBytes("description"))
							log["element"] = "request_uri"
							metrics.GetCWA.WithLabelValues(
								log["category"],
								log["remote_addr"],
								log["request_uri"],
								log["status"],
							).Inc()
							tags := ""
							for vv := range v.GetArray("tags", "tag") {
								ss := v.GetArray("tags", "tag")[vv].String()
								ss = ss[1:len(ss)-1]
								tags += ss
								tags += ","
							}
							match=true
							log["attack_type"] = tags
							break
						}

						if !match{
							found, fingerprint,attack_type := Libinjection_judge(dec)
							if found{
								log["description"] = fingerprint
								log["category"] = "Common Web Attack"
								match = true
								log["attack_type"] = attack_type
							}else{
								found,fingerprint:= ml_analysis("?"+query.Encode())
								if found{
									log["description"] = fingerprint
									log["attack_type"] = "未知"
									log["category"] = "Common Web Attack"
									match = true
								}
							}
						}

						if match{
							break
						}
					}

					if match{
						break
					}

				}

			} else {
				//query, err = url.ParseQuery(log["post_data"])
				query,_:= url.QueryUnescape(log["post_data"])

				if err != nil {
					break
				}
				//log["post_data"] = query
				if len(query) > 0 && len(query) < 3000{
					cwa, _ := fastjson.Parse(con)
					for _, v := range cwa.GetArray("filters") {
						//log["category"] = cat + ": " + string(v.GetStringBytes("description"))

						// dec, err := url.QueryUnescape(strings.Join(query, ""))
						quote := regexp.QuoteMeta(query)

						match_web := matchers.IsMatch(
							string(v.GetStringBytes("rule")),
							quote,
						)

						if match_web {
							log["category"] = cat
							log["description"] = string(v.GetStringBytes("description"))
							log["element"] = "post_data"

							metrics.GetCWA.WithLabelValues(
								log["category"],
								log["remote_addr"],
								log["request_uri"],
								log["status"],
								// log[""]
							).Inc()
							match=true
							//println(string(v.GetArray("tags","tag")))
							tags := ""
							for vv := range v.GetArray("tags", "tag") {
								ss := v.GetArray("tags", "tag")[vv].String()
								ss = ss[1:len(ss)-1]
								tags += ss
								tags += "|"
							}
							log["attack_type"] = tags
							break
						}

					}

					if !match{

						found, fingerprint,attack_type := Libinjection_judge(query)
						if found{
							log["description"] = fingerprint
							log["category"] = "Common Web Attack"
							match = true
							log["attack_type"] = attack_type
						}else{
							found,fingerprint:= ml_analysis("?data="+query)
							if found{
								log["description"] = fingerprint
								log["attack_type"] = "未知"
								log["category"] = "Common Web Attack"
								match = true
							}
						}
					}


				}


			}
		case "CVE":
			req, err := url.ParseRequestURI(log["request_uri"])
			if err != nil {
				break
			}

			if isWhitelist(options, req.RequestURI()) {
				break
			}

			log["element"] = "request_uri"
			cves, _ := fastjson.Parse(con)
			for _, cve := range cves.GetArray("templates") {
				for _, r := range cve.GetArray("requests") {
					method := string(r.GetStringBytes("method"))
					if method != log["request_method"] {
						continue
					}

					for _, m := range r.GetArray("matchers") {
						for _, s := range m.GetArray("status") {
							if log["status"] == s.String() {
								status = true
							}
						}
					}

					if !status {
						break
					}

					for _, p := range r.GetArray("path") {
						diff, err := url.ParseRequestURI(
							strings.TrimPrefix(
								strings.Trim(p.String(), `"`),
								"{{BaseURL}}",
							),
						)
						if err != nil {
							continue
						}

						if len(diff.Path) <= 1 {
							continue
						}

						if req.Path != diff.Path {
							break
						}

						fq := 0
						for q := range req.Query() {
							if diff.Query().Get(q) != "" {
								fq++
							}
						}

						if fq >= len(diff.Query()) {
							match = true
						}

						if match {
							metrics.GetCVE.WithLabelValues(
								log["category"],
								log["remote_addr"],
								log["request_uri"],
								log["status"],
							).Inc()
							log["category"] = "CVE"
							log["description"] = strings.ToTitle(string(cve.GetStringBytes("id")))
							log["attack_type"] = log["description"]
							break
						}
					}
				}

				if match {
					return match,log
				}
			}
		case "Bad Crawler":
			log["element"] = "http_user_agent"

			if isWhitelist(options, log["http_user_agent"]) {
				break
			}

			for _, pat := range strings.Split(con, "\n") {
				if match_bad_crawler := matchers.IsMatch(pat, log["http_user_agent"]); match_bad_crawler {
					metrics.GetBadCrawler.WithLabelValues(
						log["remote_addr"],
						log["http_user_agent"],
						log["status"],
					).Inc()
					log["Bad Crawler"] = "True";
					break
				}
			}

		case "Bad IP Address":
			log["element"] = "remote_addr"

			if isWhitelist(options, log["remote_addr"]) {
				break
			}

			ip := "(?m)^" + log["remote_addr"]
			match_bad_ip := matchers.IsMatch(ip, con)
			if match_bad_ip {
				metrics.GetBadIP.WithLabelValues(log["remote_addr"]).Inc()
				log["Bad IP"] = "True";
			}

		case "Bad Referrer":
			log["element"] = "http_referer"
			if isWhitelist(options, log["http_referer"]) {
				break
			}

			if log["http_referer"] == "-" {
				break
			}

			req, err := url.Parse(log["http_referer"])
			if err != nil {
				break
			}
			ref := "(?m)^" + req.Host

			match_bad_referer := matchers.IsMatch(ref, con)
			if match_bad_referer {
				metrics.GetBadReferrer.WithLabelValues(log["http_referer"]).Inc()
				log["Bad Referrer"] = "True"
				//return match, log
			}

		case "Directory Bruteforce":
			log["element"] = "request_uri"

			if isWhitelist(options, log["request_uri"]) ||
				matchers.IsMatch("^20(0|4)$", log["status"]) ||
				matchers.IsMatch("^3[0-9]{2}$", log["status"]) {
				break
			}

			req, err := url.Parse(log["request_uri"])
			if err != nil {
				break
			}
			match_db := false
			if req.Path != "/" {
				match_db = matchers.IsMatch(trimFirst(req.Path), con)
			}

			if match_db && (!match) {
				metrics.GetDirBruteforce.WithLabelValues(
					log["remote_addr"],
					log["request_uri"],
					log["status"],
				).Inc()
				log["category"] = "Directory Bruteforce"
				log["description"] = "检测到路径爆破"
				log["attack_type"] = req.Path
				match = true
			}
		}

		// if match {
		// 	return match, log
		// }
	}

	return match, log
}

func trimFirst(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
}

func isWhitelist(options *common.Options, find string) bool {
	whitelist := options.Configs.Rules.Threat.Whitelists
	for i := 0; i < len(whitelist); i++ {
		match := matchers.IsMatch(whitelist[i], find)
		if match {
			return true
		}
	}

	return false
}
