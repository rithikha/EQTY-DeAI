import json
import base58
import base64
from typing import Dict, List, Optional

from eqty_sdk import init, generate_manifest, purge_integrity_store
from eqty_sdk import DID, DID_ALGORITHMS
from eqty_sdk import Custom
from eqty_sdk import Computation
from eqty_sdk import Declaration

init()

did = DID.new(DID_ALGORITHMS.ED25519, name="Build system", description="The build system identifier used to register integrity statements")
did.set_active()

class Component:
    def __init__(self, component_data: Dict):
        self.name = component_data.get('name')
        self.version = component_data.get('version')
        self.type = component_data.get('type')
        self.description = component_data.get('description')
        self.supplier = component_data.get('supplier')
        self.licenses = component_data.get('licenses', [])
        self.purl = component_data.get('purl')
        self.bom_ref = component_data.get('bom-ref')
        self.security = ComponentSecurity(component_data, self.bom_ref)
        self.integrity = None

    def __repr__(self):
        return f"Component(bom_ref='{self.bom_ref}')"


class ComponentSecurity:
    def __init__(self, component_data: Dict, bom_ref: str):
        self.bom_ref = bom_ref
        self.hashes = component_data.get('hashes', [])
        self.signature = component_data.get('signature')
        self.evidence = component_data.get('evidence')

    def __repr__(self):
        return f"ComponentSecurity(bom_ref='{self.bom_ref}')"


class Assessor:
    def __init__(self, assessor_data: Dict):
        self.bom_ref = assessor_data.get('bom-ref')
        self.third_party = assessor_data.get('thirdParty', False)
        self.organization_name = assessor_data.get('organizationName')
        self.organization_email = assessor_data.get('organizationEmail')
        
        # Flatten individual fields
        individual = assessor_data.get('individual', {})
        self.individual_name = individual.get('name')
        self.individual_email = individual.get('email')

    def __repr__(self):
        return f"Assessor(bom_ref='{self.bom_ref}')"


class EvidenceData:
    def __init__(self, data_item: Dict):
        self.name = data_item.get('name')
        self.media_type = data_item.get('mediaType')
        self.encoding = data_item.get('encoding')
        self.data = data_item.get('data')
        
        # Decode base64 data if present
        self.decoded_data = None
        if self.encoding == 'base64' and self.data:
            try:
                self.decoded_data = base64.b64decode(self.data).decode('utf-8')
            except Exception as e:
                self.decoded_data = f"Failed to decode: {e}"

    def __repr__(self):
        return f"EvidenceData(name='{self.name}')"


class Evidence:
    def __init__(self, evidence_data: Dict):
        self.name = evidence_data.get('name')
        self.description = evidence_data.get('description')
        self.data_items = []
        
        for data_item in evidence_data.get('data', []):
            evidence_data_obj = EvidenceData(data_item)
            self.data_items.append(evidence_data_obj)

    def __repr__(self):
        return f"Evidence(name='{self.name}', data_items={len(self.data_items)})"


class Claim:
    def __init__(self, claim_data: Dict):
        self.bom_ref = claim_data.get('bom-ref')
        self.target = claim_data.get('target')
        self.predicate = claim_data.get('predicate')
        self.mitigation_strategies = claim_data.get('mitigationStrategies', [])
        self.reasoning = claim_data.get('reasoning')
        self.signature = claim_data.get('signature')
        
        # Parse evidence objects
        self.evidence = []
        for evidence_data in claim_data.get('evidence', []):
            evidence_obj = Evidence(evidence_data)
            self.evidence.append(evidence_obj)

    def __repr__(self):
        return f"Claim(bom_ref='{self.bom_ref}')"


class Attestation:
    def __init__(self, attestation_data: Dict):
        self.summary = attestation_data.get('summary')
        self.assessor = attestation_data.get('assessor')
        self.claims = []
        
        # Parse claims from map section
        for map_item in attestation_data.get('map', []):
            requirement = map_item.get('requirement')
            for claim_data in map_item.get('claims', []):
                claim = Claim(claim_data)
                claim.requirement = requirement  # Add requirement to claim
                self.claims.append(claim)

    def __repr__(self):
        return f"Attestation(summary='{self.summary}')"


def parse_cyclonedx_components(json_file_path: str):
    """
    Parse components from a CycloneDX SBOM JSON file and return components with embedded security data, dependencies, assessors, and attestations.
    """
    with open(json_file_path, 'r') as f:
        sbom_data = json.load(f)
    
    components = []
    
    for component_data in sbom_data.get('components', []):
        component = Component(component_data)
        components.append(component)
    
    dependencies = sbom_data.get('dependencies', [])
    
    # Parse declarations section
    declarations = sbom_data.get('declarations', {})
    
    # Parse assessors
    assessors = []
    for assessor_data in declarations.get('assessors', []):
        assessor = Assessor(assessor_data)
        assessors.append(assessor)
    
    # Parse attestations
    attestations = []
    for attestation_data in declarations.get('attestations', []):
        attestation = Attestation(attestation_data)
        attestations.append(attestation)

    # Parse timestamp
    timestamp = sbom_data.get('metadata', {}).get('timestamp', None)
    
    return components, dependencies, assessors, attestations, timestamp


def sha256_to_content_id(sha256_hash: str) -> str:
    """
    Convert a SHA-256 hash into a proper IPFS CID (Content Identifier).
    
    CID structure: <cidv1-multicodec><content-type-multicodec><content-multihash>
    - CIDv1 multicodec: 0x01
    - Content type multicodec (raw): 0x55
    - Multihash: <hash-function-code><digest-length><digest>
      - SHA-256 function code: 0x12
      - Digest length: 32 bytes (0x20)
    """
    # Convert hex string to bytes
    hash_bytes = bytes.fromhex(sha256_hash)
    
    # Build multihash: <hash-function-code><digest-length><digest>
    # SHA-256 function code: 0x12, digest length: 32 (0x20)
    multihash = bytes([0x12, 0x20]) + hash_bytes
    
    # Build CIDv1: <cidv1-multicodec><content-type-multicodec><multihash>
    # CIDv1 multicodec: 0x01, raw content type: 0x55
    cid_bytes = bytes([0x01, 0x55]) + multihash
    
    # Encode as base58btc with 'z' prefix
    return 'z' + base58.b58encode(cid_bytes).decode('ascii')


# Parse components from the SBOM file
components, dependencies, assessors, attestations, timestamp = parse_cyclonedx_components('cyclonedx_sbom.json')

# Create a map with bom-ref as key and Component as value
component_map = {component.bom_ref: component for component in components}

# Create a map with bom-ref as key and content ID as value
def get_content_id_for_component(component):
    """Get the content ID for a component if it has a SHA-256 hash."""
    if component.security.hashes:
        for hash_data in component.security.hashes:
            if hash_data.get('alg') == 'SHA-256':
                return sha256_to_content_id(hash_data.get('content'))
    return None

content_id_map = {component.bom_ref: get_content_id_for_component(component) for component in components}

# Display the parsed components
print(f"Parsed {len(components)} components from CycloneDX SBOM:")
for component in components:
    print(f"  - {component}")
    print(f"    name: {component.name}")
    print(f"    version: {component.version}")
    print(f"    type: {component.type}")
    print(f"    description: {component.description}")
    print(f"    supplier: {component.supplier}")
    print(f"    licenses: {component.licenses}")
    print(f"    purl: {component.purl}")
    print(f"    bom_ref: {component.bom_ref}")
    print(f"    security: {component.security}")
    if component.security.hashes:
        print(f"      hashes: {component.security.hashes}")
        for hash_data in component.security.hashes:
            if hash_data.get('alg') == 'SHA-256':
                content_id = sha256_to_content_id(hash_data.get('content'))
                print(f"      content_id: {content_id}")
    if component.security.signature:
        print(f"      signature: {component.security.signature}")
    if component.security.evidence:
        print(f"      evidence: {component.security.evidence}")
    print()

print(f"\nComponent map has {len(component_map)} entries:")
for bom_ref, component in component_map.items():
    print(f"  {bom_ref} -> {component.name} v{component.version}")

# Create data statement for each component
for component in components:
    content_id = ""
    if component.security.hashes:
        for hash_data in component.security.hashes:
            if hash_data.get('alg') == 'SHA-256':
                content_id = sha256_to_content_id(hash_data.get('content'))
                break
    
    data_integrity = Custom.from_cid(content_id, component.type,
        name=component.name,
        version=component.version,
        type=component.type,
        description=component.description,
        supplier=component.supplier["name"],
        licenses=component.licenses[0]["license"]["id"],
        purl=component.purl,
        bom_ref=component.bom_ref
    )

    component.integrity = data_integrity

# Create computation statements from component dependency relationships
print(f"\nDependency relationships by Content ID:")
for dependency in dependencies:
    ref = dependency.get('ref')
    depends_on = dependency.get('dependsOn', [])
    
    ref_content_id = content_id_map.get(ref, 'No Content ID')
    ref_component = component_map.get(ref)
    ref_name = ref_component.name if ref_component else 'Unknown'

    computation_kwargs = {
        "name": f"{ref_name} build",
        "description": f"The building of {ref_name}"
    }
    
    computation = Computation.new(**computation_kwargs).add_output_cid(ref_content_id)
    
    for dep_ref in depends_on:
        dep_content_id = content_id_map.get(dep_ref, 'No Content ID')
        dep_component = component_map.get(dep_ref)
        dep_name = dep_component.name if dep_component else 'Unknown'
        print(f"    depends on -> {dep_name} ({dep_content_id})")

        computation.add_input_cid(dep_content_id)

    print()
    
    computation.finalize()

# Create DIDs from assessors
print(f"\nParsed {len(assessors)} assessors:")
for assessor in assessors:
    print(f"  - {assessor}")
    print(f"    organization_name: {assessor.organization_name}")
    print(f"    organization_email: {assessor.organization_email}")
    print(f"    individual_name: {assessor.individual_name}")
    print(f"    individual_email: {assessor.individual_email}")
    print(f"    third_party: {assessor.third_party}")
    print(f"    bom_ref: {assessor.bom_ref}")
    print()

    DID.new(DID_ALGORITHMS.ED25519,
        organization_name=assessor.organization_name,
        organization_email=assessor.organization_email,
        individual_name=assessor.individual_name,
        individual_email=assessor.individual_email,
        third_party=assessor.third_party,
        bom_ref=assessor.bom_ref
    )

# Create declarations from attestations
print(f"\nParsed {len(attestations)} attestations:")
for attestation in attestations:
    print(f"  - {attestation}")
    print(f"    summary: {attestation.summary}")
    print(f"    assessor: {attestation.assessor}")
    print(f"    claims ({len(attestation.claims)}):")
    for claim in attestation.claims:
        print(f"      - {claim}")
        print(f"        requirement: {claim.requirement}")
        print(f"        target: {claim.target}")
        print(f"        predicate: {claim.predicate}")
        print(f"        reasoning: {claim.reasoning}")
        print(f"        mitigation_strategies: {claim.mitigation_strategies}")
        print(f"        evidence: {len(claim.evidence)} items")
        for evidence in claim.evidence:
            print(f"          - {evidence}")
            print(f"            description: {evidence.description}")
            for data_item in evidence.data_items:
                print(f"            data: {data_item}")
                print(f"              name: {data_item.name}")
                print(f"              media_type: {data_item.media_type}")
                print(f"              encoding: {data_item.encoding}")
                print(f"              data: {data_item.data}")
                if data_item.decoded_data:
                    print(f"              decoded_data: {data_item.decoded_data}")
        if claim.signature:
            print(f"        signature: {claim.signature.get('algorithm', 'N/A')}")
        
        # Create EQTY Declaration for each claim
        target_content_id = content_id_map.get(claim.target, 'No Content ID')
        
        # Map CycloneDX claim to EQTY Declaration structure
        declaration_data = {
            "type": "declaration",  # CycloneDX.declarations.claims
            "subjectLine": claim.predicate,  # CycloneDX.declarations.claims.predicate
            "statement": claim.reasoning,  # CycloneDX.declarations.claims.reasoning
            "submittedAt": timestamp,  # CycloneDX.metadata.timestamp
            "submittedBy": f"assessor:{attestation.assessor}",  # CycloneDX.declarations.attestations.assessor
            "attachmentCid": [item.decoded_data for evidence in claim.evidence for item in evidence.data_items if item.decoded_data],  # CycloneDX.declarations.claims.evidence
            "controlCid": [claim.requirement],  # CycloneDX.declarations.attestations.map.requirement
            "extra": {
                "target": claim.target,
                "bom_ref": claim.bom_ref,
                "mitigation_strategies": claim.mitigation_strategies,
                "signature": claim.signature
            }
        }
        
        print()
        print(f"        Created Declaration (target_content_id: {target_content_id}):")
        print(f"          type: {declaration_data['type']}")
        print(f"          subjectLine: {declaration_data['subjectLine']}")
        print(f"          statement: {declaration_data['statement']}")
        print(f"          submittedAt: {declaration_data['submittedAt']}") # TODO
        print(f"          submittedBy: {declaration_data['submittedBy']}") # TODO
        print(f"          attachmentCid: {declaration_data['attachmentCid']}") # TODO
        print(f"          controlCid: {declaration_data['controlCid']}") # TODO
        print(f"          extra: {declaration_data['extra']}")
        print()

        declaration = Declaration.new(declaration_data['subjectLine'], declaration_data['statement']) \
            .add_extra("target", declaration_data['extra']['target']) \
            .add_extra("bom_ref", declaration_data['extra']['bom_ref']) \
            .add_extra("mitigation_strategies", declaration_data['extra']['mitigation_strategies']) \
            .add_extra("signature", declaration_data['extra']['signature']) \
            .finalize()
            # .add_attachment_cid(cid) \
            # .add_control_cid(cid) \
        component_map.get(declaration_data['extra']['target']).integrity.add_declaration(declaration)

    print()

# Export manifest
generate_manifest("manifest.json")
purge_integrity_store()