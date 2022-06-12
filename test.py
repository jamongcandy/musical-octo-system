from owlready2 import *
from bs4 import BeautifulSoup
import regex

onto = get_ontology("http://test.org/cwe.owl")

with open(
    "C:/Users/jeonghwan/Desktop/study/ontology/cwe_schema_latest.xsd",
    "r",
    encoding="utf8",
) as f:
    xsd_file = f.read()

soup = BeautifulSoup(xsd_file, "xml")

enums = soup.find_all("xs:simpleType", {"name": regex.compile("^.*Enumeration$")})


with onto:

    class Weakness(Thing):
        pass

    class Enumeration(Thing):
        pass

    for enum in enums:
        newEnumerationClass = types.new_class(enum["name"], (Enumeration,))
        for e in enum.find_all("xs:enumeration"):
            newEnumerationClass(name=e["value"])

    ################ C#, F# 같은건 #때문에 인스턴스가 안만들어진다!

    class StructuredText(Thing):
        pass

    class GlobalTypes(Thing):
        pass

    # ID
    class hasID(Weakness >> int):
        pass

    # Name
    class hasName(Weakness >> str):
        pass

    # Abstraction
    class AbstractionEnumeration(Enumeration):
        pass

    class hasAbstraction(Weakness >> AbstractionEnumeration):
        pass

    # Structure
    class StructureEnumeration(Enumeration):
        pass

    class hasStructure(Weakness >> StructureEnumeration):
        pass

    # Status
    class StatusEnumeration(Enumeration):
        pass

    class hasStatus(Weakness >> StatusEnumeration):
        pass

    # Description
    class hasDescription(Weakness >> str):
        pass

    # Extended_Description
    class StructuredTextType(StructuredText):
        pass

    class hasExtendedDescription(Weakness >> StructuredTextType):
        pass

    # Related_Weaknesses
    class RelatedWeaknessesType(GlobalTypes):
        pass

    class RelatedWeakness(RelatedWeaknessesType):
        pass

    class RelatedNatureEnumeration(Enumeration):
        pass

    class hasNature(RelatedWeakness >> RelatedNatureEnumeration):
        pass

    class hasCWEID(RelatedWeakness >> int):
        pass

    class hasViewID(RelatedWeakness >> int):
        pass

    class hasChainID(RelatedWeakness >> int):
        pass

    class OrdinalEnumeration(Enumeration):
        pass

    class hasOrdinal(RelatedWeakness >> OrdinalEnumeration):
        pass

    class hasRelatedWeaknesses(Weakness >> RelatedWeaknessesType):
        pass

    # Weakness_Ordinalities
    class WeaknessOrdinalitiesType(GlobalTypes):
        pass

    class WeaknessOrdinality(WeaknessOrdinalitiesType):
        pass

    class OrdinalityEnumeration(Enumeration):
        pass

    class hasOrdinality(WeaknessOrdinality >> OrdinalityEnumeration):
        pass

    class hasDescription(WeaknessOrdinality >> str):
        pass

    class hasWeaknessOrdinalities(Weakness >> WeaknessOrdinalitiesType):
        pass

    # Applicable_Platforms
    class ApplicablePlatformsType(GlobalTypes):
        pass

    class Language(ApplicablePlatformsType):
        pass

    class LanguageNameEnumeration(Enumeration):
        pass

    ##################################################################################
    # class hasName(ApplicablePlatformsType.Language >> LanguageNameEnumeration):
    #     pass
    class hasName(ObjectProperty):
        domain = [Language]
        range = [LanguageNameEnumeration]

    ##################### 이름이 똑같은게 있어서 안된다!!#################################

    class Operating_System(ApplicablePlatformsType):
        pass

    class Architecture(ApplicablePlatformsType):
        pass

    class Technology(ApplicablePlatformsType):
        pass

    class hasApplicablePlatforms(Weakness >> ApplicablePlatformsType):
        pass

    # Background_Details
    # Alternate_Terms
    # Modes_Of_Introduction
    # Exploitation_Factors
    # Likelihood_Of_Exploit
    # Common_Consequences
    # Detection_Methods
    # Potential_Mitigations
    # Demonstrative_Examples
    # Observed_Examples
    # Functional_Areas
    # Affected_Resources
    # Taxonomy_Mappings
    # Related_Attack_Patterns
    # References
    # Notes
    # Content_History


onto.save(file="cwe.owl", format="rdfxml")
