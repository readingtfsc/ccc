package utils

import (
	"bytes"
	"encoding/xml"
)

type StringMap map[string]string

func (s StringMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {

	tokens := []xml.Token{start}

	for key, value := range s {
		t := xml.StartElement{Name: xml.Name{"", key}}
		tokens = append(tokens, t, xml.CharData(value), xml.EndElement{t.Name})
	}

	tokens = append(tokens, xml.EndElement{start.Name})

	for _, t := range tokens {
		err := e.EncodeToken(t)
		if err != nil {
			return err
		}
	}

	err := e.Flush()
	if err != nil {
		return err
	}

	return nil
}

func MapToXmlString(m map[string]string) string {
	output, err := xml.MarshalIndent(StringMap(m), "", " ")
	if err != nil {
		return ""
	}

	return string(output)
}

func XmlStringToMap(data []byte) map[string]string {
	r := bytes.NewReader(data)

	// result
	m := make(map[string]string)
	// the current value stack
	values := make([]string, 0)
	// parser

	p := xml.NewDecoder(r)
	for token, err := p.Token(); err == nil; token, err = p.Token() {
		switch t := token.(type) {
		case xml.CharData:
			// push
			values = append(values, string([]byte(t)))
		case xml.EndElement:
			if t.Name.Local == "langs" {
				continue
			}
			if t.Name.Local == "xml" {
				continue
			}
			m[t.Name.Local] = values[len(values)-1]
			// pop
			values = values[:len(values)]
		}
	}
	// done
	return m

}
