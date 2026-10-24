from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from keenetic_manager.core import Route
from keenetic_manager.metadata import MetadataStore, Note, resolve_ptr, rdap_owner, identify_network, normalize_domain


class TestMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"192.168.1.1.json"
        self.store=MetadataStore(self.path)

    def test_private_store_not_router(self):
        self.store.set_manual("185.244.36.22/32", "ZFilm")
        self.assertEqual(self.store.get("185.244.36.22").site_label, "ZFilm")
        loaded=MetadataStore(self.path)
        self.assertEqual(loaded.get("185.244.36.22").manual, "ZFilm")
        self.assertIn("ZFilm",self.path.read_text(encoding="utf8"))

    def test_domain_for_host_does_not_tag_broad_route(self):
        self.store.add_site("www.zfilm.homes", ["185.244.36.22"])
        self.assertEqual(self.store.get("185.244.36.22/32").site_label,"www.zfilm.homes")
        self.assertEqual(self.store.get("185.244.0.0/16").site_label,"")

    def test_sites_are_distinct_hostnames_on_shared_ip(self):
        self.store.add_site("zfilm.homes",["185.244.36.22"])
        self.store.add_site("www.zfilm.homes",["185.244.36.22"])
        self.assertEqual(self.store.get("185.244.36.22").sites, ["zfilm.homes", "www.zfilm.homes"])

    def test_manual_precedence(self):
        self.store.add_site("zfilm.homes",["185.244.36.22"])
        self.store.set_manual("185.244.36.22","Мой сайт")
        self.store.add_enrichment("185.244.36.22",ptr="host.provider.net",verified=False,owner="A provider")
        n=self.store.get("185.244.36.22")
        self.assertEqual(n.site_label,"Мой сайт")
        self.assertEqual(n.source,"Вручную")
        self.store.set_manual("185.244.36.22", "")
        self.assertEqual(self.store.get("185.244.36.22").site_label,"zfilm.homes")

    def test_json_export_annotations_only(self):
        self.store.set_manual("185.244.36.22", "ZFilm")
        r=Route(ipaddress.IPv4Network("185.244.36.22/32"),"Wireguard2",True)
        blob=json.loads(self.store.to_json_export([r]))
        self.assertEqual(blob[0]["annotation"]["manual"],"ZFilm")
        self.assertEqual(blob[0]["interface"],"Wireguard2")
        self.assertNotIn("annotation",r.to_dict())

    def test_host_scope(self):
        with patch.dict(os.environ,{"LOCALAPPDATA":str(self.path.parent)}):
            a=MetadataStore.default_path("192.168.1.1")
            b=MetadataStore.default_path("192.168.0.1")
        self.assertNotEqual(a,b)

    def test_corrupted_database_raises_no_router_mutations(self):
        self.path.write_text("!",encoding="utf8")
        with self.assertRaises(ValueError):
            MetadataStore(self.path)

    def test_ptr_forward_verified(self):
        def resolver(ip):return ("hosting.example.net.",[],[ip])
        def forward(host):return ("hosting.example.net",[],["185.244.36.22"])
        self.assertEqual(resolve_ptr("185.244.36.22",resolver=resolver,forward=forward),("hosting.example.net",True))

    def test_ptr_mismatch_not_confident(self):
        self.assertEqual(resolve_ptr("185.244.36.22",resolver=lambda _:("foo.example.net",[],[]),
                                      forward=lambda _:("foo.example.net",[],["8.8.8.8"])),("foo.example.net",False))

    def test_private_ptr_skipped(self):
        self.assertEqual(resolve_ptr("192.168.1.1",resolver=lambda _ : (_ for _ in ()).throw(AssertionError())),("",False))

    def test_rdap_owner_separate_from_site(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def read(self,_):return b'{"name":"EXAMPLE-NETWORK","cidr0_cidrs":[]}'
        self.assertEqual(rdap_owner("185.244.36.22",opener=lambda req,timeout:Response()),"EXAMPLE-NETWORK")
        self.store.add_enrichment("185.244.36.22",owner="EXAMPLE-NETWORK")
        self.assertEqual(self.store.get("185.244.36.22").site_label, "")
        self.assertEqual(self.store.get("185.244.36.22").owner, "EXAMPLE-NETWORK")

    def test_rdap_private_skipped(self):
        self.assertEqual(rdap_owner("10.0.0.1",opener=lambda *_: (_ for _ in ()).throw(AssertionError())),"")

    def test_prefix_ptr_skipped(self):
        self.assertEqual(identify_network("87.245.0.0/16",reverse=lambda ip: (_ for _ in ()).throw(AssertionError()),
                                          owner_lookup=lambda ip:"PROVIDER"),{"ptr":"","verified":False,"owner":"PROVIDER"})

    def test_invalid_domains(self):
        for d in ("https://foo", "no-dots", "bad..example.com"):
            with self.assertRaises(ValueError):
                normalize_domain(d)


if __name__=="__main__":
    unittest.main()
