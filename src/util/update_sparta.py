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
            and not ref.get("external_id").startswith("D3")
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
        sparta_uri = D3F[f"{sparta_id}"]
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
                    D3F[f"{sparta_id.split('.')[0]}"],
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
        sparta_uri = D3F[f"{sparta_id}"]
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
                f"{src.get(rel['target_ref'])['external_references'][0]['external_id']}"
            ]
            g.add((sparta_uri, D3F.related, related_uri))

        # TODO: Add links to common attack patterns when CAPEC extensions have been added to the ontology
        # for capec in threat.get("external_references", []):
        #     if capec.get("source_name") == "capec-mitre":
        #         capec_id = capec.get("external_id")
        #         capec_uri = D3F[f"CAPEC-{capec_id}"]
        #         g.add((sparta_uri, D3F.related, capec_uri))


def add_countermeasure_to_graph(src, g, d3fend_graph, countermeasure):
    """
    Add a SPARTA Countermeasure to the graph
    :param src: MemoryStore
    :param g: Graph
    :param d3fend_graph: Graph of D3FEND Ontology
    :param countermeasure: STIX course-of-action object that is a SPARTA Countermeasure
    """
    sparta_id = get_sparta_id(countermeasure)
    # If the countermeasure has a SPARTA ID, add it to the graph
    if sparta_id is not None:
        # Create a URI for the SPARTA Countermeasure
        sparta_uri = D3F[f"{sparta_id}"]
        g.add((sparta_uri, RDF.type, D3F.SPARTACountermeasure))
        g.add((sparta_uri, RDF.type, OWL.NamedIndividual))
        g.add((sparta_uri, RDFS.label, Literal(countermeasure["name"])))
        sparta_url = next(
            (
                ref.get("url")
                for ref in countermeasure["external_references"]
                if ref.get("source_name") == "sparta"
            ),
            None,
        )
        g.add((sparta_uri, RDFS.seeAlso, URIRef(sparta_url)))
        g.add((sparta_uri, D3F.definition, Literal(countermeasure["description"])))
        g.add((sparta_uri, D3F["sparta-id"], Literal(sparta_id)))

        # Add relationships to related SPARTA classes
        for rel in src.relationships(countermeasure):
            d3fend_id = next(
                (
                    ref["external_id"]
                    for ref in src.get(rel["target_ref"])["external_references"]
                    if ref["source_name"] == "D3FEND"
                ),
                None,
            )
            # if the related object is a D3FEND technique then it is a countermeasure for that technique
            if d3fend_id is not None:
                d3fend_name = (
                    next(
                        (
                            ref["url"]
                            for ref in src.get(rel["target_ref"])["external_references"]
                            if ref["source_name"] == "D3FEND"
                        ),
                        None,
                    )
                    .replace("https://d3fend.mitre.org/technique/d3f:", "")
                    .replace("/", "")
                )
                if d3fend_name is not None:
                    d3fend_technique = D3F[d3fend_name]
                    g.add((sparta_uri, D3F["enabled-by"], d3fend_technique))
            # else if the related object is a SPARTA technique then it is a countermeasure for that technique
            elif (
                src.get(rel["target_ref"])["type"] == "attack-pattern"
                and sparta_id != "CM0000"
            ):
                related_uri = D3F[
                    f"{src.get(rel['target_ref'])['external_references'][0]['external_id']}"
                ]
                g.add((sparta_uri, D3F.counters, related_uri))

        # for NIST control mappings referenced as external references in the countermeasure
        for ref in countermeasure.get("external_references", []):
            if ref.get("url").startswith(
                "https://sparta.aerospace.org/countermeasures/references/"
            ):
                nist_control_id = (
                    ref.get("external_id").replace("(", "_").replace(")", "")
                )
                nist_control = D3F["NIST_SP_800-53_R5_" + nist_control_id]
                # g.add((sparta_uri, D3F.related, URIRef(ref.get('url'))))
                g.add((sparta_uri, D3F.related, nist_control))


def get_sparta_graph(sparta_path, d3fend_graph):
    """
    Get a graph of SPARTA Techniques and Threats
    :param sparta_path: Path to SPARTA JSON data
    :param d3fend_graph: Graph of D3FEND Ontology
    :return: Graph of SPARTA Techniques and Threats
    """
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

    countermeasures = src.query(
        [
            Filter("type", "=", "course-of-action"),
            Filter("external_references.source_name", "=", "sparta"),
        ]
    )

    # Create a new graph
    g = Graph()

    # Add SPARTA Techniques to the graph
    for tech in techniques:
        add_technique_to_graph(src, g, tech)

    # Add SPARTA Threats to the graph
    for threat in threats:
        add_threat_to_graph(src, g, threat)

    # Add SPARTA Countermeasures to the graph
    for countermeasure in countermeasures:
        add_countermeasure_to_graph(src, g, d3fend_graph, countermeasure)

    return g


def main(SPARTA_VERSION="1.6"):

    d3fend_graph = Graph()
    d3fend_graph.parse("src/ontology/d3fend-protege.sparta.ttl")

    sparta_graph = get_sparta_graph(
        f"data/sparta_data_v{SPARTA_VERSION}.json", d3fend_graph
    )

    d3fend_graph += sparta_graph

    d3fend_graph.serialize(
        destination="src/ontology/d3fend-protege.sparta.ttl", format="turtle"
    )


if __name__ == "__main__":
    version = sys.argv[1]
    main(SPARTA_VERSION=version)
