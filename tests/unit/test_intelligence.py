import pytest

from scoutx.plugins.builtin.intelligence.plugin import (
    _get_hosts,
    _score_hosts,
    _build_tech_intelligence,
    _build_priority_queue,
)

def test_get_hosts_standard():
    probe_data = {
        "hosts": [
            {"hostname": "api.example.com", "technologies": ["nginx", "django"]},
            {"hostname": "dev.example.com", "technologies": []},
        ]
    }
    hosts = _get_hosts(probe_data)
    assert len(hosts) == 2
    assert hosts[0]["hostname"] == "api.example.com"
    assert "django" in hosts[0]["technologies"]


def test_get_hosts_legacy():
    probe_data = {
        "alive_hosts": ["test.example.com"],
        "alive_urls": ["https://test.example.com"]
    }
    hosts = _get_hosts(probe_data)
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "test.example.com"
    assert hosts[0]["technologies"] == []


def test_score_hosts():
    hosts = [
        {"hostname": "api.example.com", "technologies": ["django"]},
        {"hostname": "dev.example.com", "technologies": []},
    ]
    
    ports_data = {
        "results": {
            "1.2.3.4": [{"port": 22}, {"port": 80}, {"port": 445}],
            "1.2.3.5": [80, 443]
        }
    }
    
    endpoints_data = {
        "endpoints": [
            {"categories": ["admin"]},
            {"categories": ["api", "data"]},
        ]
    }
    
    secrets_data = {
        "findings": [
            {"severity": "critical"},
            {"severity": "high"},
        ]
    }
    
    ssl_data = {
        "issues": [
            {"hostname": "dev.example.com", "type": "expired"}
        ]
    }
    
    scores = _score_hosts(hosts, ports_data, endpoints_data, secrets_data, ssl_data)
    
    assert len(scores) == 2
    
    # We expect some substantial scoring because 445 (SMB) = +20, 22 (SSH) = +5 globally
    # plus secrets (critical=30, high=20), etc.
    # So scores will likely hit max out (100)
    
    # Since all issues besides SSL and Tech apply to ALL hosts globally (due to the way _score_hosts works),
    # dev will have a slightly higher score if not maxed out, or same if capped at 100.
    
    assert scores[0]["score"] > 0
    assert "score" in scores[0]
    assert "risk_level" in scores[0]


def test_build_tech_intelligence():
    hosts = [
        {"hostname": "blog.example.com", "technologies": ["WordPress", "PHP", "MySQL"]},
        {"hostname": "api.example.com", "technologies": ["Next.js", "Express"]},
    ]
    
    intel = _build_tech_intelligence(hosts)
    
    # Check that known technologies were picked up
    techs = {item["technology"].lower(): item for item in intel}
    assert "wordpress" in techs
    assert "php" in techs
    assert "next.js" in techs
    assert "express" in techs
    
    assert "blog.example.com" in techs["wordpress"]["hosts"]


def test_build_priority_queue():
    host_scores = [
        {"hostname": "crit.com", "score": 85, "risk_level": "critical", "breakdown": ["Secrets: +40"]},
        {"hostname": "low.com", "score": 15, "risk_level": "low", "breakdown": ["Port 80: +5"]},
        {"hostname": "safe.com", "score": 5, "risk_level": "low", "breakdown": []},
    ]
    
    pq = _build_priority_queue(host_scores, {}, {})
    
    assert len(pq) == 2  # safe.com < 10, excluded
    assert pq[0]["hostname"] == "crit.com"
    assert "Critical risk score" in pq[0]["reasons"]
    assert "Immediate manual investigation" in pq[0]["suggested_actions"]
