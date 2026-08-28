package oval

type root struct {
	Generator struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator"`
	Definitions struct {
		Definition []Definition `xml:"definition"`
	} `xml:"definitions"`
	Tests   Tests   `xml:"tests"`
	Objects Objects `xml:"objects"`
	States  States  `xml:"states"`
}

type Definition struct {
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Class    string `xml:"class,attr" json:"class,omitempty"`
	Metadata struct {
		Title    string `xml:"title" json:"title,omitempty"`
		Affected struct {
			Family   string `xml:"family,attr" json:"family,omitempty"`
			Platform string `xml:"platform" json:"platform,omitempty"`
		} `xml:"affected" json:"affected,omitzero"`
		Reference []struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"description,omitempty"`
		Advisory    struct {
			From     string `xml:"from,attr" json:"from,omitempty"`
			Severity string `xml:"severity" json:"severity,omitempty"`
			Rights   string `xml:"rights" json:"rights,omitempty"`
			Issued   struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitzero"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitzero"`
			Cve []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Cwe    string `xml:"cwe,attr" json:"cwe,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Public string `xml:"public,attr" json:"public,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitzero"`
		} `xml:"advisory" json:"advisory,omitzero"`
	} `xml:"metadata" json:"metadata,omitzero"`
	Criteria Criteria `xml:"criteria" json:"criteria,omitzero"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr" json:"operator,omitempty"`
	Criterias  []Criteria  `xml:"criteria" json:"criterias,omitempty"`
	Criterions []Criterion `xml:"criterion" json:"criterions,omitempty"`
}

type Criterion struct {
	TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
}

type RpminfoTest struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type Textfilecontent54Test struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type Tests struct {
	RpminfoTest           []RpminfoTest           `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	Textfilecontent54Test []Textfilecontent54Test `xml:"textfilecontent54_test" json:"textfilecontent54_test,omitempty"`
}

type RpminfoObject struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Name    string `xml:"name" json:"name,omitempty"`
}

type Textfilecontent54Object struct {
	Xmlns    string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Path     string `xml:"path" json:"path,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
	Pattern  struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"pattern" json:"pattern,omitzero"`
	Instance struct {
		Text     string `xml:",chardata" json:"text,omitempty"`
		Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
	} `xml:"instance" json:"instance,omitzero"`
}

type Objects struct {
	RpminfoObject           []RpminfoObject           `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	Textfilecontent54Object []Textfilecontent54Object `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
}

type RpminfoState struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Evr     *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"evr" json:"evr,omitempty"`
}

type Textfilecontent54State struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Text    struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"text" json:"text,omitzero"`
}

type States struct {
	RpminfoState           []RpminfoState           `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	Textfilecontent54State []Textfilecontent54State `xml:"textfilecontent54_state" json:"textfilecontent54_state,omitempty"`
}
