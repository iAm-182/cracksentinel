package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"gamecrack-scanner/internal/filetype"
	"gamecrack-scanner/internal/model"
	"gamecrack-scanner/internal/obf"
	"gamecrack-scanner/internal/pe"
)

type importIOC struct {
	funcs    []string
	category string
	severity int
	desc     string
}

var importIOCs = map[string]importIOC{
	obf.S("MzQqLy4="): {
		funcs:    []string{obf.S("HT8uET8jODU7KD4JLjsuPw=="), obf.S("HT8uET8jCS47Lj8="), obf.S("FzsqDDMoLi87NhE/Ixs="), obf.S("HT8uHDUoPz0oNS80Pg0zND41LQ==")},
		category: obf.S("MzQqLy4="),
		severity: 6,
		desc:     obf.S("PT80PygzOXozNCovLnobChN6cjE/Izg1Oyg+ejUoejc1Lyk/eikuOy4/c3p3ei0/OzF6NTR6My4pejUtNA=="),
	},
	obf.S("MT8jNjU9PT8o"): {
		funcs:    []string{obf.S("HT8uGykjNDkRPyMJLjsuPw=="), obf.S("CT8uDTM0PjUtKRI1NTEfIhs="), obf.S("CT8uDTM0PjUtKRI1NTEfIg0="), obf.S("HT8uCDstEzQqLy4eOy47"), obf.S("CD89MykuPygIOy0TNCovLh4/LDM5Pyk=")},
		category: obf.S("MT8jNjU9PT8o"),
		severity: 30,
		desc:     obf.S("MT8jODU7KD51MzQqLy56OTsqLi8oP3obChM="),
	},
	obf.S("MzQwPzkuMzU0"): {
		funcs:    []string{obf.S("DSgzLj8KKDU5PykpFz83NSgj"), obf.S("GSg/Oy4/CD83NS4/DjIoPzs+"), obf.S("DDMoLi87Nhs2NjU5HyI="), obf.S("DDMoLi87NgooNS4/OS4fIg=="), obf.S("FC4PNDc7KgwzPy0VPAk/OS4zNTQ="), obf.S("CT8uDjIoPzs+GTU0Lj8iLg=="), obf.S("Cy8/Lz8PKT8oGwoZ"), obf.S("CC42FzUsPxc/NzUoIw==")},
		category: obf.S("MzQwPzkuMzU0"),
		severity: 30,
		desc:     obf.S("Kig1OT8pKXozNDA/OS4zNTR6GwoT"),
	},
	obf.S("OSg/Pj80LjM7Ng=="): {
		funcs:    []string{obf.S("GSgjKi4PNCooNS4/OS4eOy47"), obf.S("GSg/Ph80Lzc/KDsuPxs="), obf.S("GSg/Ph80Lzc/KDsuPw0="), obf.S("Fik7HzQvNz8oOy4/FjU9NTQJPykpMzU0KQ=="), obf.S("GSg/Pgg/Oz4b")},
		category: obf.S("KS4/OzY/KA=="),
		severity: 25,
		desc:     obf.S("OSg/Pj80LjM7NnU5NTUxMz96Pj85KCMqLjM1NHobChM="),
	},
	obf.S("PyI8MzY="): {
		funcs:    []string{obf.S("DwgWHjUtNDY1Oz4ONRwzNj8="), obf.S("EzQuPyg0Py4VKj80Gw=="), obf.S("EzQuPyg0Py4ZNTQ0PzkuGw=="), obf.S("Ei4uKhUqPzQIPysvPykuGw=="), obf.S("Ei4uKgk/ND4IPysvPykuGw=="), obf.S("EzQuPyg0Py4IPzs+HDM2Pw=="), obf.S("DQkbCS47KC4vKg=="), obf.S("KT80Pg=="), obf.S("OTU0ND85Lg==")},
		category: obf.S("ND8uLTUoMQ=="),
		severity: 12,
		desc:     obf.S("ND8uLTUoMXU/IjwzNnobChM="),
	},
	obf.S("OTYzKjg1Oyg+"): {
		funcs:    []string{obf.S("HT8uGTYzKjg1Oyg+HjsuOw=="), obf.S("FSo/NBk2Myo4NTsoPg=="), obf.S("HzcqLiMZNjMqODU7KD4=")},
		category: obf.S("KS4/OzY/KA=="),
		severity: 15,
		desc:     obf.S("OTYzKjg1Oyg+ejs5OT8pKXobChM="),
	},
	obf.S("Kj8oKTMpLj80OT8="): {
		funcs:    []string{obf.S("CD89CT8uDDs2Lz8fIhs="), obf.S("CD89CT8uDDs2Lz8fIg0="), obf.S("GSg/Oy4/CT8oLDM5Pxs="), obf.S("CS47KC4JPygsMzk/Gw==")},
		category: obf.S("Kj8oKTMpLj80OT8="),
		severity: 12,
		desc:     obf.S("Kj8oKTMpLj80OT96GwoT"),
	},
	obf.S("Pj8pLigvOS4zLD8="): {
		funcs:    []string{obf.S("GSgjKi4fNDkoIyou"), obf.S("GSgjKi4dPzQRPyM="), obf.S("HDM0PhwzKCkuHDM2Pxs="), obf.S("FzUsPxwzNj8b"), obf.S("Hj82Py4/HDM2Pxs=")},
		category: obf.S("KDs0KTU3LTsoPw=="),
		severity: 8,
		desc:     obf.S("PDM2P3U/NDkoIyouMzU0ehsKE3pyKDs0KTU3LTsoP3czKTJz"),
	},
}

var stealerCombo = model.Finding{
	Rule:     obf.S("OTU3ODUFKS4/OzY/KAUpLjs5MQ=="),
	Category: obf.S("KS4/OzY/KA=="),
	Severity: 25,
	Detail:   obf.S("OCg1LSk/KHo5KD8+PzQuMzs2enF6OTYzKjg1Oyg+enF6ND8uLTUoMXobChMpejk1NzgzND8+enI5NjspKTM5eikuPzs2Pyh6KS47OTFz"),
}

var reDiscord = regexp.MustCompile(obf.S("Mi4uKilgdXVyPjMpOTUoPjsqKgZ0OTU3Jj4zKTk1KD4GdDk1N3N1OyozdS0/ODI1NTEpdQY+IWttdmhqJ3UBBi13ByFsanZjaic="))
var reTelegram = regexp.MustCompile(obf.S("BjgGPiFidmtqJ2ABG3cAO3cgandjBXcHIWlqdm5vJwY4"))
var reEncoded = regexp.MustCompile(obf.S("cmUzc3J3PyZ3PzQ5Jnc/NDk1Pj8+OTU3Nzs0PnMGKXABG3cAO3cgandjcXVnByFuanYn"))
var reCradle = regexp.MustCompile(obf.S("cmUzc3I5Lyg2Ji09Py4mEzQsNTE/dw0/OAg/Ky8/KS4mEzQsNTE/dx8iKig/KSkzNTQmMz8iJjk/KC4vLjM2JjgzLik7PjczNCY3KTIuOyYoPz0pLChpaHMGKXEBBAYoBjQHIWp2a2hqJzIuLiopZWB1dQ=="))
var reIPPort = regexp.MustCompile(obf.S("BjgGPiFrdmknBnQGPiFrdmknBnQGPiFrdmknBnQGPiFrdmknYAY+IWh2bycGOA=="))
var reBase64Blob = regexp.MustCompile(obf.S("ARt3ADt3IGp3Y3F1ByFoamp2J2chanZoJw=="))
var reWallet = regexp.MustCompile(obf.S("cmUzc3ItOzY2Py4GdD47LiY3Py47NzspMSY/IjU+LykmPzY/OS4oLzcmKT8/PgF6BQcqMig7KT8mBjg3ND83NTQzOQY4JgY4FjU9MzR6HjsuOwY4Jjk1NTEzPykGdCkrNjMuPyYqOykpLTUoPikGdC4iLiY7Ly41PDM2NnM="))
var reKeylogWord = regexp.MustCompile(obf.S("cmUzc3IGODE/IzY1PXI9PygmPTM0PSY9Pz5zZQY4JjE/IykuKDUxPyY5NjMqODU7KD56ZT0oOzgmPSg7ODg/KCYpLj87Nj8oJj8iPDM2Lig7LnM="))
var reRunKey = regexp.MustCompile(obf.S("cmUzc3IZLygoPzQuDD8oKTM1NAYGBgYILzQmKTkyLjspMSkGKXF1OSg/Oy4/JhQ/LXcJPygsMzk/Jig/PQYpcTs+PgYpcRIRFhdz"))
var reVM = regexp.MustCompile(obf.S("cmUzc3IsNy07KD8mLDMoLi87Njg1IiYsODUiJik7ND44NSIzPyYtMzQ/AQQ7dyAHcw=="))

// scriptRules are kind-specific indicators for script payloads (.bat/.cmd/
// .ps1/.vbs/.js/.hta). A script has no import table, so its behaviour is
// described by the APIs and paths it mentions — these rules are the script
// equivalent of the PE import-IOC table.
type keywordRule struct {
	rule     string
	category string
	severity int
	desc     string
	any      []string // match if ANY needle appears
	all      []string // match if ALL needles appear
}

var scriptRules = []keywordRule{
	{
		rule: obf.S("KTkoMyouBTIzPj4/NAU/Ij85"), category: obf.S("Pyw7KTM1NA=="), severity: 25,
		desc: obf.S("MjM+Pj80dy0zND41LXo/Ij85Ly4zNTQ="),
		any: []string{
			obf.S("KS47KC53Kig1OT8pKXp3LTM0PjUtKS4jNj96MjM+Pj80"), obf.S("dy0zND41LSkuIzY/ejIzPj4/NA=="),
			obf.S("dy16MjM+Pj80"), obf.S("LTM0PjUtKS4jNj8yMz4+PzQ="), obf.S("OSg/Oy4/NTgwPzkucngtKTkoMyoudCkyPzY2eHM="),
			obf.S("LSk5KDMqLnQpMj82Ng=="), obf.S("LSk5KDMqLnQpMj82NnQoLzQ="), obf.S("KTI/NjZ0OyoqNjM5Oy4zNTQ="),
		},
	},
	{
		rule: obf.S("KTkoMyouBTkoPz4FKjsuMik="), category: obf.S("KS4/OzY/KA=="), severity: 20,
		desc: obf.S("OCg1LSk/KHUqKDU8MzY/ejkoPz4/NC4zOzZ6KjsuMno7OTk/KSk="),
		any: []string{
			obf.S("OTUqI3czLj83en4/NCxg"), obf.S("OTUqI3czLj83"), obf.S("OyoqPjsuOwY2NTk7NgY9NTU9Nj8GOTIoNTc/"),
			obf.S("OyoqPjsuOwYoNTs3MzQ9Bjc1IDM2Njs="), obf.S("NjU9MzR6PjsuOw=="), obf.S("OTU1MTM/KXQpKzYzLj8="),
			obf.S("Bj01NT02PwY5Mig1Nz8GLyk/KHo+Oy47"), obf.S("LT84ej47Ljs="), obf.S("NjU5OzZ6KS47Lj8="),
		},
	},
	{
		rule: obf.S("KTkoMyouBTI1NTEFOyoz"), category: obf.S("MT8jNjU9PT8o"), severity: 20,
		desc: obf.S("MT8jNjU9PTM0PXU5KD8+PzQuMzs2dz4/OSgjKi4zNTR6GwoTeig/PD8oPzQ5Pz4="),
		any: []string{
			obf.S("PT8uOykjNDkxPyMpLjsuPw=="), obf.S("KT8uLTM0PjUtKTI1NTE/Ig=="), obf.S("PT8uMT8jKS47Lj8="),
			obf.S("OSgjKi4vNCooNS4/OS4+Oy47"), obf.S("PT8uPDUoPz0oNS80Pi0zND41LQ=="), obf.S("PT8uMT8jODU7KD4pLjsuPw=="),
		},
	},
	{
		rule: obf.S("KTkoMyouBT41LTQ2NTs+BT8iPzk="), category: obf.S("Pig1Kio/KA=="), severity: 30,
		desc: obf.S("PjUtNDY1Oz53OzQ+dz8iPzkvLj96KjsuLj8oNA=="),
		all:  []string{obf.S("Mz8i")},
		any: []string{
			obf.S("PjUtNDY1Oz4pLigzND0="), obf.S("PjUtNDY1Oz48MzY/"), obf.S("MzQsNTE/dy0/OCg/Ky8/KS4="),
			obf.S("KSMpLj83dDQ/LnQtPzg5NjM/NC4="), obf.S("ND8udC0/ODk2Mz80Lg=="), obf.S("NykyLjt6Mi4uKg=="),
			obf.S("OT8oLi8uMzZ6dy8oNjk7OTI/"), obf.S("ODMuKTs+NzM0enUuKDs0KTw/KA=="),
		},
	},
	{
		rule: obf.S("KTkoMyouBT8iPDM2"), category: obf.S("OWg="), severity: 20,
		desc: obf.S("NS8uODUvND56PyI8MzYuKDsuMzU0ejkyOzQ0PzY="),
		any: []string{
			obf.S("MzQsNTE/dy0/OCg/Ky8/KS4="), obf.S("KSMpLj83dDQ/LnQtPzg5NjM/NC4="), obf.S("Lyo2NTs+KS4oMzQ9"),
			obf.S("Lyo2NTs+PDM2Pw=="), obf.S("KT80Pnc3OzM2Nz8pKTs9Pw=="), obf.S("KTcuKjk2Mz80Lg=="), obf.S("Mi4uKi0/OCg/Ky8/KS4="),
			obf.S("OS8oNnp3KQ=="), obf.S("LT0/Lnp3Kw=="),
		},
	},
	{
		rule: obf.S("KTkoMyouBT4/PD80Pj8oBTgjKjspKQ=="), category: obf.S("Pyw7KTM1NA=="), severity: 30,
		desc: obf.S("Gwx1Hx4Iei47Nyo/KDM0PQ=="),
		any: []string{
			obf.S("KT8udzcqKig/PD8oPzQ5Pw=="), obf.S("PjMpOzg2P3coPzs2LjM3Pzc1NDMuNSgzND0="), obf.S("PjMpOzg2P3coPzs2LjM3P3c3NTQzLjUoMzQ9"),
			obf.S("OzcpMy8uMzYp"), obf.S("OzcpMzM0My48OzM2Pz4="), obf.S("Oz4+dzcqKig/PD8oPzQ5Pw=="), obf.S("dz8iOTYvKTM1NCo7LjI="),
			obf.S("LTM0PjUtKXo+Pzw/ND4/KA=="), obf.S("OzcpM3Q+NjY="), obf.S("OzcpMy8uMzYpdD42Ng=="),
		},
	},
	{
		rule: obf.S("KTkoMyouBTU4PC8pOTsuMzU0"), category: obf.S("Pyw7KTM1NA=="), severity: 15,
		desc: obf.S("KTkoMyouejU4PC8pOTsuMzU0enV6PzQ5NT4/PnoqOyM2NTs+"),
		any: []string{
			obf.S("PCg1Nzg7KT9sbikuKDM0PQ=="), obf.S("KjUtPygpMj82Nnp3Pw=="), obf.S("dz80OTU+Pz45NTc3OzQ+"),
			obf.S("dz85eg=="), obf.S("OTI7KHI="), obf.S("Mz8icjQ/LXc1ODA/OS4="), obf.S("MzQsNTE/dz8iKig/KSkzNTQ="),
			obf.S("KT8udz8iPzkvLjM1NCo1NjM5I3o4Iyo7KSk="), obf.S("OCMqOykp"), obf.S("MjM+Pj80enc/NDk="),
		},
	},
	{
		rule: obf.S("KTkoMyouBSo/KCkzKS4/NDk/"), category: obf.S("Kj8oKTMpLj80OT8="), severity: 15,
		desc: obf.S("KTkoMyoudzY/LD82eio/KCkzKS4/NDk/"),
		any: []string{
			obf.S("KTkyLjspMSl6dTkoPzsuPw=="), obf.S("KD89ejs+PnoyMTY3"), obf.S("KD89ejs+PnoyMTkv"),
			obf.S("ND8tdyk/KCwzOT8="), obf.S("KS47KC4vKno8NTY+Pyg="), obf.S("KTI/NjZgKS47KC4vKg=="),
			obf.S("OS8oKD80Liw/KCkzNTQGKC80"), obf.S("OS8oKD80Liw/KCkzNTQGKC80NTQ5Pw=="),
		},
	},
	{
		rule: obf.S("KTkoMyouBTkoIyouNQU3MzQ/KA=="), category: obf.S("NzM0Pyg="), severity: 20,
		desc: obf.S("OSgjKi41NzM0Pyh6OTU0PDM9Lyg7LjM1NA=="),
		any: []string{
			obf.S("KS4oOy4vN3EuOSo="), obf.S("KS4oOy4vN3EpKTY="), obf.S("IjcoMz0="), obf.S("NzM0Pyg+"), obf.S("OSovNzM0Pyg="),
			obf.S("NDM5PzI7KTI="), obf.S("KDs0PjU3Ig=="),
		},
	},
	{
		rule: obf.S("KTkoMyouBSg/LD8oKT8FKTI/NjY="), category: obf.S("OWg="), severity: 30,
		desc: obf.S("KD8sPygpP3cpMj82Nnp1ejM0Lj8oOzkuMyw/ejg7OTE+NTUoeiooMzczLjMsPw=="),
		any: []string{
			obf.S("ND8tdzU4MD85LnopIykuPzd0ND8udCk1OTE/Lil0LjkqOTYzPzQu"), obf.S("KTU5MT8ucnM="),
			obf.S("NDl6dz8="), obf.S("NDk7Lnp3Pw=="), obf.S("ODspMnp3M3pkfA=="), obf.S("KjUtPygpMj82Nnp3NDUqenc5"),
			obf.S("KTU5MT8udCk1OTE/Lg=="), obf.S("Ki4jdCkqOy00"),
		},
	},
}

// shortcutRules apply to .lnk/.url/.pif files. A shortcut is a binary whose
// argument string carries the real payload — the classic obf.S("NjQxeigvNCl6KjUtPygpMj82Ng==")
// dropper vector.
var shortcutRules = []keywordRule{
	{
		rule: obf.S("KTI1KC45Ly4FPyI/OQ=="), category: obf.S("Pig1Kio/KA=="), severity: 25,
		desc: obf.S("KTI1KC45Ly56LjsoPT8ueigvNCl6O3opOSgzKi51MzQuPygqKD8uPyh6MjUpLg=="),
		any: []string{
			obf.S("KjUtPygpMj82Ng=="), obf.S("OTc+dD8iP3p1OQ=="), obf.S("OTc+enU5"), obf.S("NykyLjs="), obf.S("LSk5KDMqLg=="),
			obf.S("OSk5KDMqLg=="), obf.S("KC80PjY2aWg="), obf.S("KD89KSwoaWg="), obf.S("OT8oLi8uMzY="), obf.S("ODMuKTs+NzM0"),
			obf.S("PyIqNjUoPyh0PyI/"), obf.S("BgYpIykuPzdpaAYG"),
		},
	},
	{
		rule: obf.S("KTI1KC45Ly4FKD83NS4/"), category: obf.S("OWg="), severity: 20,
		desc: obf.S("KTI1KC45Ly56KjUzNC4pejsuejt6KD83NS4/eg8IFg=="),
		any:  []string{obf.S("Mi4uKmB1dQ=="), obf.S("Mi4uKilgdXU=")},
	},
	{
		rule: obf.S("KTI1KC45Ly4FMjM+Pj80"), category: obf.S("Pyw7KTM1NA=="), severity: 10,
		desc: obf.S("KTI1KC45Ly56MjM+Pyl6My4pei0zND41LXp1ejQ1eiwzKTM4Nj96Mzk1NA=="),
		any:  []string{obf.S("KTI1LS0zND41LWdq"), obf.S("LTM0PjUtKS4jNj8="), obf.S("NzM0MzczID8+"), obf.S("MjM+Pj80")},
	},
}

// docRules apply to .doc/.docm/.xlsm/.rtf/.pdf: macro or DDE launchers.
var docRules = []keywordRule{
	{
		rule: obf.S("PjU5BTc7OSg1"), category: obf.S("Pig1Kio/KA=="), severity: 25,
		desc: obf.S("PjU5Lzc/NC56Nzs5KDV6Oy8uNXc/Ij85Ly4/KXo5NT4/"),
		any: []string{
			obf.S("Oy8uNTUqPzQ="), obf.S("PjU5Lzc/NC4FNSo/NA=="), obf.S("LTUoMTg1NTEFNSo/NA=="), obf.S("KS84ejsvLjU1Kj80"),
			obf.S("KTI/NjZy"), obf.S("Oy8uNQU5NjUpPw=="), obf.S("LDgqKDUwPzku"), obf.S("KTI/NjYqOyM2NTs+"),
		},
	},
	{
		rule: obf.S("PjU5BT4+Pw=="), category: obf.S("Pig1Kio/KA=="), severity: 30,
		desc: obf.S("Hh4fejsvLjV3PyI/OS8uMzU0ejwzPzY+"),
		any:  []string{obf.S("Pj4/Oy8uNQ=="), obf.S("Pj4/eg=="), obf.S("Nyk/Ijk/Ng=="), obf.S("Pj4/KT8oLD8o")},
	},
}

// archiveRules apply to container files (zip/7z/rar/iso) — a double extension
// inside an archive is the classic obf.S("MzQ0NTkvNS8pdCo+PHQ/Ij8=") dropper shape.
var archiveRules = []keywordRule{
	{
		rule: obf.S("Oyg5MjMsPwU+NS84Nj8FPyIu"), category: obf.S("Pig1Kio/KA=="), severity: 20,
		desc: obf.S("PjUvODY/ej8iLj80KTM1NHpyPDM2P3o+Myk9LzMpPz56Oyl6PjU5Lzc/NC51Mzc7PT9z"),
		any: []string{
			obf.S("dCo+PHQ/Ij8="), obf.S("dD41OXQ/Ij8="), obf.S("dDAqPXQ/Ij8="), obf.S("dCo0PXQ/Ij8="), obf.S("dC4iLnQ/Ij8="),
			obf.S("dCI2KXQ/Ij8="), obf.S("dCAzKnQ/Ij8="), obf.S("dDcqbnQ/Ij8="), obf.S("dDAqPXQpOSg="), obf.S("dCo+PHQpOSg="),
			obf.S("dC4iLnQpOSg="), obf.S("dD0zPHQpOSg="), obf.S("dDApdD8iPw=="),
		},
	},
	{
		rule: obf.S("Oyg5MjMsPwU1PDwzOT8FNzs5KDU="), category: obf.S("Pig1Kio/KA=="), severity: 20,
		desc: obf.S("Oyg5MjMsP3o5NTQuOzM0KXo7ejc7OSg1dz80Ozg2Pz56NTw8Mzk/ej41OS83PzQu"),
		any:  []string{obf.S("dD41OTc="), obf.S("dCI2KTc="), obf.S("dCoqLjc="), obf.S("dCI2Ozc="), obf.S("dCI2Ng==")},
	},
}

var crackWhitelist = []string{
	obf.S("CA8UHw=="), obf.S("HTU2Pjg/KD0="), obf.S("CTc7KC4JLj87Nx83Lw=="), obf.S("CTc7KC4JLj87Nw=="), obf.S("HBYO"), obf.S("GxYTaGtp"),
	obf.S("EhUVHhYPFw=="), obf.S("GRUeHwI="), obf.S("GQoD"), obf.S("CRETHggVDQ=="), obf.S("CB8WFRseHx4="), obf.S("ChYbABs="), obf.S("Dh8UFREf"),
	obf.S("KS4/OzcFPzcv"), obf.S("GTU2Phk2Mz80LhY1Oz4/KA=="), obf.S("OSg/Ozc2Ozg="),
}

// strongStringIOCs are string-level findings that veto the emulator-cap below:
// a trojanized emu almost always adds one of these (C2 URL, encoded command,
// credential targets). Import-only findings don't veto — hooking imports are
// core emulator behavior.
var strongStringIOCs = map[string]bool{
	obf.S("PjMpOTUoPgUtPzgyNTUx"): true, obf.S("Lj82Pz0oOzcFLjUxPzQ="): true, obf.S("KikFPzQ5NT4/Pg=="): true,
	obf.S("PjUtNDY1Oz4FOSg7PjY/"): true, obf.S("MyoFKjUoLg=="): true, obf.S("LTs2Nj8uBTgoNS0pPygFLjsoPT8u"): true,
	obf.S("MT8jNjU9BS01KD4="): true, obf.S("MT8jNjU9BS01KD5o"): true, obf.S("Kj8oKTMpLj80OT8FKS4oMzQ9"): true,
}

// actionCategories are the finding categories that describe
// something the file DOES. They only matter when the file can act.
var actionCategories = map[string]bool{
	obf.S("OWg="):             true,
	obf.S("Pyw7KTM1NA=="):     true,
	obf.S("Pig1Kio/KA=="):     true,
	obf.S("KS4/OzY/KA=="):     true,
	obf.S("MT8jNjU9PT8o"):     true,
	obf.S("Kj8oKTMpLj80OT8="): true,
	obf.S("ND8uLTUoMQ=="):     true,
	obf.S("KDs0KTU3LTsoPw=="): true,
	obf.S("NzM0Pyg="):         true,
	obf.S("MzQwPzkuMzU0"):     true,
	obf.S("OSg/Pj80LjM7Ng=="): true,
}

// IsCapability reports whether a finding describes what the file CAN
// do rather than what it DOES.
//
// The import-based findings are capability: hooking the keyboard,
// injecting, using the network. A crack emulator has capability and no
// intent. The string-based findings are intent: a C2 URL, a browser
// credential target, a run key. The scoring policy caps the capability
// bucket so a legitimate tool that does five things at once does not
// add up to MALICIOUS.
func IsCapability(rule string) bool {
	if strings.HasPrefix(rule, obf.S("MzcqBQ==")) {
		return true
	}
	for _, r := range []string{obf.S("MT8jNjU9BS01KD5o"), obf.S("ODspP2xuBTg2NTg="), obf.S("KTs0Pjg1IgU5Mj85MQ=="), obf.S("Kjs5MT8o"), obf.S("PjUuND8u"), obf.S("Kj8FKjsoKT8="), obf.S("OSgjKi4/KAU0NQUoOy0FKT85LjM1NCk="), obf.S("PzQ5KCMqLj8+BSo7IzY1Oz4="), obf.S("NDU0KS47ND47KD4FKT85LjM1NCk="), obf.S("NDUFKD87Pjs4Nj8FKS4oMzQ9KQ=="), obf.S("Oy8uNQUvNCo7OTE/Pg=="), obf.S("LzQqOzkxBTw7MzY/Pg==")} {
		if rule == r {
			return true
		}
	}
	return false
}

type MatchInput struct {
	Kind  filetype.Kind
	PE    *pe.Info
	Strs  []string
	Bytes []byte
	Path  string
	// Signed reports that the PE carries an Authenticode certificate
	// table. The certificate is NOT verified, but its presence is
	// still meaningful: a random trojanized crack rarely carries one.
	Signed bool
}

// yaraCategory maps a YARA rule name to the internal finding category it
// duplicates. The YARA engine and the internal engine both detect the same
// malware families, so without this mapping one signal (e.g. a Discord
// webhook) is counted twice — 40 from the internal regex plus 20 from YARA —
// which inflates a single finding into a 60-point score and pushes innocent
// files into MALICIOUS.
func YaraCategory(rule string) string {
	r := strings.ToLower(rule)
	switch {
	case strings.Contains(r, obf.S("PzM5Oyg=")):
		return obf.S("Lj8pLjwzNj8=")
	case strings.Contains(r, obf.S("PjMpOTUoPg==")), strings.Contains(r, obf.S("Lj82Pz0oOzc=")), strings.Contains(r, obf.S("OWg=")):
		return obf.S("OWg=")
	case strings.Contains(r, obf.S("KjUtPygpMj82Ng==")), strings.Contains(r, obf.S("PzQ5NT4/Pg==")), strings.Contains(r, obf.S("NTg8Lyk=")), strings.Contains(r, obf.S("KTs0Pjg1Ig==")):
		return obf.S("Pyw7KTM1NA==")
	case strings.Contains(r, obf.S("MT8jNjU9")):
		return obf.S("MT8jNjU9PT8o")
	case strings.Contains(r, obf.S("KS4/OzY=")), strings.Contains(r, obf.S("OSg/Pj80LjM7Ng==")), strings.Contains(r, obf.S("LTs2Nj8u")), strings.Contains(r, obf.S("OCg1LSk/KA==")):
		return obf.S("KS4/OzY/KA==")
	case strings.Contains(r, obf.S("MzQwPzku")), strings.Contains(r, obf.S("MjU2NjUt")):
		return obf.S("MzQwPzkuMzU0")
	case strings.Contains(r, obf.S("Kj8oKTMpLg==")), strings.Contains(r, obf.S("KC80BTE/Iw==")):
		return obf.S("Kj8oKTMpLj80OT8=")
	case strings.Contains(r, obf.S("NzM0Pyg=")), strings.Contains(r, obf.S("KS4oOy4vNw==")):
		return obf.S("NzM0Pyg=")
	case strings.Contains(r, obf.S("OSg7OTE=")), strings.Contains(r, obf.S("Pzcv")), strings.Contains(r, obf.S("MzQ8NQ==")):
		return obf.S("MzQ8NQ==")
	}
	return obf.S("")
}

// Match evaluates every detection layer against one file.
//
// Layer order matters: the generic string/regex pass runs first, then the
// kind-specific passes (script / shortcut / doc / archive) which are more
// specific and therefore carry higher confidence.
func Match(in MatchInput) (findings []model.Finding, whitelistHits []string) {
	if in.PE != nil {
		findings = append(findings, matchImports(in.PE, in.Signed)...)
	}
	findings = append(findings, matchStrings(in.Strs)...)
	findings = append(findings, matchBytes(in.Bytes)...)
	findings = append(findings, matchKind(in.Kind, in.Strs, in.Path)...)
	whitelistHits = matchWhitelist(in.Strs)
	if isEmuLike(in.Strs, findings) {
		whitelistHits = append(whitelistHits, obf.S("HxcPBQkOHxsXGwoT"))
	}
	if len(findings) == 0 && len(whitelistHits) > 0 {
		findings = append(findings, model.Finding{
			Rule:     obf.S("OSg7OTEFLTIzLj82Myku"),
			Category: obf.S("MzQ8NQ=="),
			Severity: 0,
			Detail:   obf.S("MTQ1LTR6OSg7OTF1PzcvNjsuNSh6KTM9NDsuLyg/YHo=") + strings.Join(whitelistHits, obf.S("dno=")),
		})
	}
	// A file that cannot execute cannot be a payload. The evidence is
	// still reported, but it stops counting towards the score: a
	// base64 PowerShell command in a notes file, an IP:port in a log
	// or a "schtasks /create" line in a readme are not threats while
	// the file sits there as text.
	if in.Kind == filetype.KindText {
		for i := range findings {
			if findings[i].Severity > 0 && actionCategories[findings[i].Category] {
				findings[i].Severity = 0
				findings[i].Detail = obf.S("AS4/Ii56PDM2P3Z6OTs0NDUuej8iPzkvLj8Heg==") + findings[i].Detail
			}
		}
	}
	return findings, whitelistHits
}

// matchKind dispatches to the kind-specific rule sets. Each set is only
// applied to the file class it was designed for, which keeps signal high and
// false positives low (a .doc mentioning obf.S("KjUtPygpMj82Ng==") is not a script).
func matchKind(kind filetype.Kind, strs []string, path string) []model.Finding {
	var out []model.Finding
	switch kind {
	case filetype.KindScript:
		out = append(out, matchKeywords(strs, scriptRules)...)
	case filetype.KindShortcut:
		out = append(out, matchKeywords(strs, shortcutRules)...)
	case filetype.KindDoc:
		out = append(out, matchKeywords(strs, docRules)...)
	case filetype.KindArchive:
		out = append(out, matchKeywords(strs, archiveRules)...)
	}
	// A double extension is meaningful for ANY file kind, not just archives:
	// obf.S("MzQsNTM5P3QqPjx0PyI/") sitting loose in a game folder is a dropper.
	if path != obf.S("") && hasDoubleExt(path) {
		out = append(out, model.Finding{
			Rule:     obf.S("PjUvODY/BT8iLj80KTM1NA=="),
			Category: obf.S("Pig1Kio/KA=="),
			Severity: 20,
			Detail:   obf.S("PjUvODY/ej8iLj80KTM1NHpyPjMpPS8zKT8+ej8iPzkvLjs4Nj9zYHo=") + filepath.Base(path),
		})
	}
	return out
}

// matchKeywords evaluates a keyword rule set against a file's strings.
// Rules are matched case-insensitively on the lowercased string set.
func matchKeywords(strs []string, set []keywordRule) []model.Finding {
	if len(strs) == 0 {
		return nil
	}
	lower := make([]string, 0, len(strs))
	for _, s := range strs {
		lower = append(lower, strings.ToLower(s))
	}
	var out []model.Finding
	for _, kr := range set {
		if kr.all != nil {
			if !containsAll(lower, kr.all) {
				continue
			}
		} else if len(kr.any) > 0 && !containsAny(lower, kr.any) {
			continue
		}
		hit := obf.S("")
		for _, s := range lower {
			if matchesRule(s, kr) {
				hit = s
				break
			}
		}
		if hit == obf.S("") {
			hit = obf.S("cjc7LjkyPz5z")
		}
		out = append(out, model.Finding{
			Rule:     kr.rule,
			Category: kr.category,
			Severity: kr.severity,
			Detail:   kr.desc + obf.S("YHo=") + trunc(hit, 70),
		})
	}
	return out
}

func matchesRule(s string, kr keywordRule) bool {
	for _, n := range kr.any {
		if strings.Contains(s, n) {
			return true
		}
	}
	if kr.all != nil {
		return containsAll([]string{s}, kr.all)
	}
	return false
}

func containsAny(strs []string, needles []string) bool {
	for _, s := range strs {
		for _, n := range needles {
			if n != obf.S("") && strings.Contains(s, n) {
				return true
			}
		}
	}
	return false
}

func containsAll(strs []string, needles []string) bool {
	for _, n := range needles {
		if n == obf.S("") {
			continue
		}
		found := false
		for _, s := range strs {
			if strings.Contains(s, n) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(needles) > 0
}

// hasDoubleExt reports a filename like obf.S("MzQsNTM5P3QqPjx0PyI/") — a document or
// image extension followed by an executable one.
func hasDoubleExt(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	parts := strings.Split(name, obf.S("dA=="))
	if len(parts) < 3 {
		return false
	}
	docExts := map[string]bool{
		obf.S("dCo+PA=="): true, obf.S("dD41OQ=="): true, obf.S("dD41OSI="): true, obf.S("dCI2KQ=="): true, obf.S("dCI2KSI="): true,
		obf.S("dDAqPQ=="): true, obf.S("dDAqPz0="): true, obf.S("dCo0PQ=="): true, obf.S("dD0zPA=="): true, obf.S("dDg3Kg=="): true,
		obf.S("dC4iLg=="): true, obf.S("dCguPA=="): true, obf.S("dDcqaQ=="): true, obf.S("dDcqbg=="): true, obf.S("dDssMw=="): true,
		obf.S("dCAzKg=="): true, obf.S("dCg7KA=="): true, obf.S("dDIuNzY="): true, obf.S("dDkpLA=="): true,
	}
	execExts := map[string]bool{
		obf.S("dD8iPw=="): true, obf.S("dCk5KA=="): true, obf.S("dDk1Nw=="): true, obf.S("dCozPA=="): true, obf.S("dDg7Lg=="): true,
		obf.S("dDk3Pg=="): true, obf.S("dCopaw=="): true, obf.S("dCw4KQ=="): true, obf.S("dDAp"): true, obf.S("dDIuOw=="): true,
		obf.S("dDA7KA=="): true, obf.S("dDcpMw=="): true,
	}
	return docExts[obf.S("dA==")+parts[len(parts)-2]] && execExts[obf.S("dA==")+parts[len(parts)-1]]
}

func matchImports(info *pe.Info, signed bool) []model.Finding {
	var out []model.Finding
	flat := map[string]bool{}
	for _, funcs := range info.Imports {
		for _, fn := range funcs {
			flat[strings.ToLower(fn)] = true
		}
	}
	cats := map[string]bool{}
	for name, ioc := range importIOCs {
		var hit []string
		for _, fn := range ioc.funcs {
			if flat[strings.ToLower(fn)] {
				hit = append(hit, fn)
			}
		}
		if len(hit) > 0 {
			sev := ioc.severity
			// A signed binary that hooks things is a tool, not a
			// payload: Google's adb, SDL2, an auto-clicker. The
			// certificate is not verified, so the finding is
			// discounted rather than dropped.
			if signed {
				sev -= 12
				if sev < 0 {
					sev = 0
				}
			}
			out = append(out, model.Finding{
				Rule:     obf.S("MzcqBQ==") + name,
				Category: ioc.category,
				Severity: sev,
				Detail:   ioc.desc + obf.S("YHo=") + strings.Join(hit, obf.S("dno=")),
			})
			cats[name] = true
		}
	}
	if cats[obf.S("OSg/Pj80LjM7Ng==")] && cats[obf.S("OTYzKjg1Oyg+")] && cats[obf.S("PyI8MzY=")] {
		out = append(out, stealerCombo)
	}
	if cats[obf.S("MT8jNjU9PT8o")] && cats[obf.S("PyI8MzY=")] {
		out = append(out, model.Finding{
			Rule:     obf.S("OTU3ODUFMT8jNjU9BT8iPDM2"),
			Category: obf.S("MT8jNjU9PT8o"),
			Severity: 20,
			Detail:   obf.S("MT8jNjU9PT8oehsKE3pxejQ/Li01KDF6PyI8MzZ6GwoTejk1NzgzND8+"),
		})
	}
	if info.Packer != obf.S("") {
		sev := 15
		if info.Packer == obf.S("LzQxNDUtNHI/NC4oNSojcw==") {
			sev = 8
		}
		out = append(out, model.Finding{
			Rule:     obf.S("Kjs5MT8o"),
			Category: obf.S("Kjs5MTM0PQ=="),
			Severity: sev,
			Detail:   obf.S("Kjs5MT8odTU4PC8pOTsuMzU0YHo=") + info.Packer,
		})
	}
	if info.Dotnet {
		out = append(out, model.Finding{
			Rule:     obf.S("PjUuND8u"),
			Category: obf.S("MzQ8NQ=="),
			Severity: 2,
			Detail:   obf.S("dBQfDno7KSk/Nzg2I3pyPj85NTcqMzY/ei0zLjJ6MzYpKiN1PjQpKiN6PDUoeig/LDM/LXM="),
		})
	}
	return out
}

func matchStrings(strs []string) []model.Finding {
	var out []model.Finding
	seen := map[string]int{}
	for _, s := range strs {
		l := strings.ToLower(s)
		switch {
		case reDiscord.MatchString(s):
			add(&out, seen, obf.S("PjMpOTUoPgUtPzgyNTUx"), obf.S("OWg="), 40, obf.S("HjMpOTUoPnotPzgyNTUxeg8IFmB6")+trunc(s, 80))
		case reTelegram.MatchString(s):
			add(&out, seen, obf.S("Lj82Pz0oOzcFLjUxPzQ="), obf.S("OWg="), 35, obf.S("Dj82Pz0oOzd6ODUuei41MT80YHo=")+trunc(s, 50))
		}
		switch {
		case reEncoded.MatchString(s):
			add(&out, seen, obf.S("KikFPzQ5NT4/Pg=="), obf.S("Pyw7KTM1NA=="), 30, obf.S("CjUtPygJMj82Nno/NDk1Pj8+ejk1Nzc7ND5geg==")+trunc(s, 100))
		case reCradle.MatchString(s):
			add(&out, seen, obf.S("PjUtNDY1Oz4FOSg7PjY/"), obf.S("Pig1Kio/KA=="), 20, obf.S("PjUtNDY1Oz56OSg7PjY/YHo=")+trunc(s, 100))
		case reIPPort.MatchString(s):
			add(&out, seen, obf.S("MyoFKjUoLg=="), obf.S("OWg="), 10, obf.S("MjsoPjk1Pj8+ehMKYCo1KC5geg==")+s)
		case reWallet.MatchString(l):
			add(&out, seen, obf.S("LTs2Nj8uBTgoNS0pPygFLjsoPT8u"), obf.S("KS4/OzY/KA=="), 15, obf.S("OCg1LSk/KHUtOzY2Py56LjsoPT8ueikuKDM0PWB6")+trunc(s, 60))
		case reKeylogWord.MatchString(l):
			add(&out, seen, obf.S("MT8jNjU9BS01KD4="), obf.S("MT8jNjU9PT8o"), 12, obf.S("MT8jNjU9PT8oei4/KDczNDU2NT0jYHo=")+trunc(s, 60))
		case reRunKey.MatchString(s):
			add(&out, seen, obf.S("Kj8oKTMpLj80OT8FKS4oMzQ9"), obf.S("Kj8oKTMpLj80OT8="), 15, obf.S("Kj8oKTMpLj80OT96KS4oMzQ9YHo=")+trunc(s, 80))
		case reVM.MatchString(l):
			add(&out, seen, obf.S("KTs0Pjg1IgU5Mj85MQ=="), obf.S("Pyw7KTM1NA=="), 8, obf.S("KTs0Pjg1InUMF3o+Py4/OS4zNTR6KS4oMzQ9YHo=")+trunc(s, 60))
		case reBase64Blob.MatchString(s):
			add(&out, seen, obf.S("ODspP2xuBTg2NTg="), obf.S("Pyw7KTM1NA=="), 6, obf.S("NjsoPT96ODspP2xuejg2NTh6cjY/NHo=")+itoa(len(s))+obf.S("cw=="))
		}
		if len(s) >= 4 && strings.Contains(l, obf.S("OykjNDkxPyMpLjsuPw==")) {
			add(&out, seen, obf.S("MT8jNjU9BS01KD5o"), obf.S("MT8jNjU9PT8o"), 5, obf.S("MT8jNjU9ehsKE3ooPzw/KD80OT8+ejM0eikuKDM0PWB6")+trunc(s, 60))
		}
	}
	return out
}

func matchBytes(b []byte) []model.Finding {
	var out []model.Finding
	for _, pat := range []struct {
		name string
		hex  []byte
		cat  string
		sev  int
		desc string
	}{
		{obf.S("PzM5Oyg="), []byte(obf.S("Am8Vewp/GhsKAW4GCgACb25yCgRzbRkZc20nfh8TGRsIdwkOGxQeGwgedxsUDhMMEwgPCXcOHwkOdxwTFh97fhJxEnA=")), obf.S("Lj8pLjwzNj8="), 100, obf.S("HxMZGwh6OzQuMywzKC8pei4/KS56PDM2Pw==")},
	} {
		if len(b) > 0 && bytesContains(b, pat.hex) {
			out = append(out, model.Finding{Rule: pat.name, Category: pat.cat, Severity: pat.sev, Detail: pat.desc})
		}
	}
	return out
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// isEmuLike reports whether the file looks like a Steam emulator DLL (TENOKE /
// Goldberg style): dominated by SteamAPI exports with no exfil/payload string
// IOCs. Hooking imports (WriteProcessMemory, SetWindowsHookEx) are normal emu
// behavior, so they don't veto — but any strong string IOC does, because a
// trojanized twin needs payload strings (C2 URLs, encoded commands, paths).
func isEmuLike(strs []string, findings []model.Finding) bool {
	emu := 0
	for _, s := range strs {
		if strings.Contains(s, obf.S("CS4/OzcbChMF")) {
			emu++
			if emu >= 50 {
				break
			}
		}
	}
	if emu < 50 {
		return false
	}
	for _, f := range findings {
		if strongStringIOCs[f.Rule] {
			return false
		}
	}
	return true
}

func matchWhitelist(strs []string) []string {
	var hits []string
	seen := map[string]bool{}
	for _, s := range strs {
		for _, w := range crackWhitelist {
			if strings.Contains(s, w) && !seen[w] {
				seen[w] = true
				hits = append(hits, w)
			}
		}
	}
	return hits
}

func add(out *[]model.Finding, seen map[string]int, rule, cat string, sev int, detail string) {
	if seen[rule] >= 2 {
		return
	}
	seen[rule]++
	*out = append(*out, model.Finding{Rule: rule, Category: cat, Severity: sev, Detail: detail})
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + obf.S("dHR0")
}

func itoa(n int) string {
	if n == 0 {
		return obf.S("ag==")
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
