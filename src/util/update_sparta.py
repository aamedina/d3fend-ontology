from stix2 import MemoryStore, Filter
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL

import sys
import re

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

sparta_categories_to_threat = {
    "None": None,
    "Prevention": "PreventionThreat",
    "Cryptography": "CryptoThreat",
    "Data": "DataThreat",
    "Spacecraft Software": "SpacecraftSoftwareThreat",
    "Ground": "GroundThreat",
    "IDS/IPS": "IntrusionThreat",
    "Single Board Computer": "SingleBoardComputerThreat",
    "Comms Link": "CommsLinkThreat",
}

aerospace_did_layer_to_threat = {
    "Prevention": "PreventionThreat",
    "Crypto": "CryptoThreat",
    "Data": "DataThreat",
    "S/C Software": "SpacecraftSoftwareThreat",
    "Ground": "GroundThreat",
    "IDS/IPS": "IntrusionThreat",
    "SBC": "SingleBoardComputerThreat",
    "Comms Link": "CommsLinkThreat",
}


def get_sparta_id(tech):
    """
    Get the SPARTA ID from a STIX Technique object
    :param tech: STIX Technique object
    :return: SPARTA ID or None
    """
    return next(
        (
            ref.get("external_id")
            for ref in tech["external_references"]
            if ref.get("source_name") == "sparta"
        ),
        None,
    )


def add_technique_to_graph(src, g, tech):
    """
    Add a SPARTA Technique to the graph
    :param src: MemoryStore
    :param g: Graph
    :param tech: STIX attack-pattern object that is a SPARTA Technique
    """
    sparta_id = get_sparta_id(tech)
    # If the technique has a SPARTA ID, add it to the graph
    if sparta_id is not None:
        # Create a URI for the SPARTA Technique
        sparta_uri = D3F[f"SPARTA-{sparta_id}"]
        g.add((sparta_uri, RDF.type, D3F.SPARTATechnique))
        g.add((sparta_uri, RDF.type, OWL.Class))
        g.add((sparta_uri, RDF.type, OWL.NamedIndividual))
        g.add((sparta_uri, RDFS.label, Literal(tech["name"].strip() + " - SPARTA")))
        sparta_url = next(
            (
                ref.get("url")
                for ref in tech["external_references"]
                if ref.get("source_name") == "sparta"
            ),
            None,
        )
        g.add((sparta_uri, RDFS.seeAlso, URIRef(sparta_url)))
        g.add((sparta_uri, D3F.definition, Literal(tech["description"])))
        g.add((sparta_uri, D3F["sparta-id"], Literal(sparta_id)))
        # NOTE: as of v1.6, SPARTA STIX data has "x_sparta_is_subtechnique" set to False for everything, so this is a workaround
        # If the SPARTA ID has a period, it is a sub-technique
        if "." in sparta_id:
            g.add(
                (
                    sparta_uri,
                    RDFS.subClassOf,
                    D3F[f"SPARTA-{sparta_id.split('.')[0]}"],
                )
            )
        else:
            # Interpret the kill chain phase name as the parent technique classified by tactic
            for obj in tech.get("kill_chain_phases", []):
                name = str("SPARTA" + obj["phase_name"] + " Technique").replace(" ", "")
                g.add((sparta_uri, RDFS.subClassOf, D3F[name]))


def add_threat_to_graph(src, g, threat):
    """
    Add a SPARTA Threat to the graph
    :param src: MemoryStore
    :param g: Graph
    :param threat: STIX attack-pattern object that is a SPARTA Threat
    """
    sparta_id = get_sparta_id(threat)
    # If the threat has a SPARTA ID, add it to the graph
    if sparta_id is not None:
        # Create a URI for the SPARTA Threat
        sparta_uri = D3F[f"SPARTA-{sparta_id}"]
        g.add((sparta_uri, RDF.type, D3F.SPARTAThreat))
        g.add((sparta_uri, RDF.type, OWL.Class))
        g.add((sparta_uri, RDF.type, OWL.NamedIndividual))
        g.add((sparta_uri, RDFS.label, Literal(threat["name"])))
        sparta_url = next(
            (
                ref.get("url")
                for ref in threat["external_references"]
                if ref.get("source_name") == "sparta"
            ),
            None,
        )
        g.add((sparta_uri, RDFS.seeAlso, URIRef(sparta_url)))
        g.add(
            (
                sparta_uri,
                D3F.definition,
                Literal(re.sub(r"^\[\"|\"\]$|\['|'\]$", "", threat["description"])),
            )
        )
        g.add((sparta_uri, D3F["sparta-id"], Literal(sparta_id)))

        # Add mapped Defense-in-Depth category to the threat as superclass
        g.add(
            (
                sparta_uri,
                RDFS.subClassOf,
                D3F[aerospace_did_layer_to_threat[threat["x_aerospace_did_layer"]]],
            )
        )

        # Add relationships to related SPARTA Techniques
        for rel in src.relationships(threat):
            related_uri = D3F[
                f"SPARTA-{src.get(rel['target_ref'])['external_references'][0]['external_id']}"
            ]
            g.add((sparta_uri, D3F.related, related_uri))

        # TODO: Add links to common attack patterns when CAPEC extensions have been added to the ontology
        # for capec in threat.get("external_references", []):
        #     if capec.get("source_name") == "capec-mitre":
        #         capec_id = capec.get("external_id")
        #         capec_uri = D3F[f"CAPEC-{capec_id}"]
        #         g.add((sparta_uri, D3F.related, capec_uri))


def get_sparta_graph(sparta_path):
    src = MemoryStore()
    src.load_from_file(sparta_path)

    techniques = src.query(
        [
            Filter("type", "=", "attack-pattern"),
            Filter("external_references.source_name", "=", "sparta"),
            Filter(
                "external_references.url",
                "contains",
                "https://sparta.aerospace.org/technique/",
            ),
            Filter("kill_chain_phases.kill_chain_name", "=", "sparta"),
        ]
    )

    threats = [
        threat
        for threat in src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("external_references.source_name", "=", "sparta"),
                Filter(
                    "external_references.url",
                    "contains",
                    "https://sparta.aerospace.org/related-work/threats/",
                ),
            ]
        )
        if threat.get("kill_chain_phases") is None
    ]

    # Create a new graph
    g = Graph()

    # Add SPARTA Techniques to the graph
    for tech in techniques:
        add_technique_to_graph(src, g, tech)

    # Add SPARTA Threats to the graph
    for threat in threats:
        add_threat_to_graph(src, g, threat)

    return g


def main(SPARTA_VERSION="1.6"):

    d3fend_graph = Graph()
    d3fend_graph.parse("src/ontology/d3fend-protege.sparta.ttl")

    sparta_graph = get_sparta_graph(f"data/sparta_data_v{SPARTA_VERSION}.json")

    d3fend_graph += sparta_graph

    d3fend_graph.serialize(
        destination="src/ontology/d3fend-protege.sparta.ttl", format="turtle"
    )


if __name__ == "__main__":
    version = sys.argv[1]
    main(SPARTA_VERSION=version)
