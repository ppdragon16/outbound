/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/url"
)

type FromLinkCreator func(link string) (dialer Dialer, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(link string) (dialers []Dialer, property *Property, err error) {
	/// Get overwritten name.
	overwrittenName, linklike := common.GetTagFromLinkLikePlaintext(link)
	links := strings.Split(linklike, "->")
	for _, link := range links {
		link = strings.TrimSpace(link)
		u, err := url.Parse(link)
		if err != nil {
			return nil, nil, err
		}
		creator, ok := fromLinkCreators[u.Scheme]
		if !ok {
			return nil, nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
		}
		s, currentProperty, err := creator(link)
		if err != nil {
			return nil, nil, fmt.Errorf("create %v: %w", link, err)
		}
		dialers = append(dialers, s)
		if property != nil {
			property.Name = fmt.Sprintf("%s->%s", property.Name, currentProperty.Name)
			property.Protocol = fmt.Sprintf("%s->%s", property.Protocol, currentProperty.Protocol)
			property.Address = fmt.Sprintf("%s->%s", property.Address, currentProperty.Address)
		}
		property = currentProperty
	}
	if overwrittenName != "" {
		property.Name = overwrittenName
	}
	return
}
