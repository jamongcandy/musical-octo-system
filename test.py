from owlready2 import *
import owlready2
from bs4 import BeautifulSoup

owlready2.JAVA_EXE = "C:\Program Files\Common Files\Oracle\Java\javapath\java.exe"

onto = get_ontology("http://test.org/cwe/")

with open(
    "C:/Users/jeonghwan/Desktop/study/ontology/cwec_v4.7.xml",
    "r",
    encoding="utf8",
) as f:
    xml_file = f.read()

soup = BeautifulSoup(xml_file, "xml")
weaknesses = soup.find_all("Weakness")

with onto:

    def addDomain(property: owlready2.prop, new_domain: owlready2.entity):
        property.domain.append(new_domain)
        property.domain = Or(property.domain)

    def addRange(property, new_range):
        property.range.append(new_range)
        property.range = Or(property.range)

    class Weakness(Thing):
        pass

    class hasID(DataProperty):
        domain = [Weakness]
        range = [int]

    class Abstraction(Thing):
        pass

    Pillar = Abstraction("Pillar")
    Class = Abstraction("Class")
    Base = Abstraction("Base")
    Variant = Abstraction("Variant")
    Compound = Abstraction("Compound")

    class hasName(DataProperty):
        domain = [Weakness]
        range = [str]

    class hasAbstraction(ObjectProperty):
        domain = [Weakness]
        range = [Abstraction]

    class isAbstractionOf(ObjectProperty):
        domain = [Abstraction]
        range = [Weakness]
        inverse_property = hasAbstraction

    class Structure(Thing):
        pass

    Chain = Structure("Chain")
    Composite = Structure("Composite")
    Simple = Structure("Simple")

    class hasStructure(ObjectProperty):
        domain = [Weakness]
        range = [Structure]

    class isStructureOf(ObjectProperty):
        domain = [Structure]
        range = [Weakness]
        inverse_property = hasStructure

    class Status(Thing):
        pass

    Deprecated = Status("Deprecated")
    Draft = Status("Draft")
    Incomplete = Status("Incomplete")
    Obsolete = Status("Obsolete")
    Stable = Status("Stable")
    Usable = Status("Usable")

    class hasStatus(ObjectProperty):
        domain = [Weakness]
        range = [Status]

    class isStatusOf(ObjectProperty):
        domain = [Status]
        range = [Weakness]
        inverse_property = hasStatus

    class hasRelationshipWith(ObjectProperty, SymmetricProperty):
        domain = [Weakness]
        range = [Weakness]

    for weakness in weaknesses:
        weakness_name = "CWE_" + str(weakness["ID"])
        weakness_individual = Weakness(weakness_name)
        weakness_individual.hasID.append(int(weakness["ID"]))
        weakness_individual.hasName.append(weakness["Name"])
        weakness_individual.hasAbstraction.append(
            getattr(onto, weakness["Abstraction"])
        )
        weakness_individual.hasStructure.append(getattr(onto, weakness["Structure"]))
        weakness_individual.hasStatus.append(getattr(onto, weakness["Status"]))
        weakness_description = weakness.find("Description")
        if weakness_description:
            weakness_individual.comment.append(weakness_description.text)
        weakness_extended_description = weakness.find("Extended_Description")
        if weakness_extended_description:
            weakness_individual.comment.append(weakness_extended_description.text)
        weakness_related_weaknesses = weakness.find("Related_Weaknesses")
        if weakness_related_weaknesses:
            for related_weakness in weakness_related_weaknesses.find_all(
                "Related_Weakness"
            ):
                id = related_weakness["CWE_ID"]
                related_weakness_individual = Weakness("CWE_" + id)
                weakness_individual.hasRelationshipWith.append(
                    related_weakness_individual
                )
                view = related_weakness["View_ID"]
                nature = related_weakness["Nature"]
                inverse_property_name = None
                transistive_property_name = None
                transistive_inverse_property_name = None
                ordianl_property_name = None
                prefix = "inCWE_" + view
                if nature == "ChildOf":
                    if related_weakness.has_attr("Ordinal"):
                        ordianl = related_weakness["Ordinal"]
                        ordianl_property_name = prefix + "_Is" + ordianl + "ChildOf"
                        inverse_ordinal_property_name = (
                            prefix + "_Is" + ordianl + "ParentOf"
                        )

                    property_name = prefix + "_IsChildOf"
                    inverse_property_name = prefix + "_IsParentOf"
                    transistive_property_name = prefix + "_IsDescendantOf"
                    transistive_inverse_property_name = prefix + "_IsAncestorOf"
                elif nature == "ParentOf":
                    if related_weakness.has_attr("Ordinal"):
                        ordianl = related_weakness["Ordinal"]
                        ordianl_property_name = prefix + "_Is" + ordianl + "ParentOf"
                        inverse_ordinal_property_name = (
                            prefix + "_Is" + ordianl + "ChildOf"
                        )

                    property_name = prefix + "_IsParentOf"
                    inverse_property_name = prefix + "_IsChildOf"
                    transistive_property_name = prefix + "_IsAncestorOf"
                    transistive_inverse_property_name = prefix + "_IsDescendantOf"
                elif nature == "StartsWith":
                    property_name = "StartsWith"
                    inverse_property_name = "IsStartingWeaknessOf"
                elif nature == "CanFollow":
                    property_name = prefix + "_CanFollow"
                    inverse_property_name = prefix + "_CanPrecede"
                elif nature == "CanPrecede":
                    property_name = prefix + "_CanPrecede"
                    inverse_property_name = prefix + "_CanFollow"
                elif nature == "RequiredBy":
                    property_name = prefix + "_isRequiredBy"
                    inverse_property_name = prefix + "_Requires"
                elif nature == "Requires":
                    property_name = prefix + "_Requires"
                    inverse_property_name = prefix + "_isRequiredBy"
                elif nature == "CanAlsoBe":
                    property_name = prefix + "_CanAlsoBe"
                elif nature == "PeerOf":
                    property_name = prefix + "_isPeerOf"
                    new_property = types.new_class(
                        property_name,
                        (
                            hasRelationshipWith,
                            SymmetricProperty,
                        ),
                    )

                new_property = types.new_class(property_name, (hasRelationshipWith,))
                new_property.domain.append(Weakness)
                new_property.range.append(Weakness)
                getattr(weakness_individual, property_name).append(
                    related_weakness_individual
                )
                if ordianl_property_name is not None:
                    ordinal_property = types.new_class(
                        ordianl_property_name, (hasRelationshipWith,)
                    )
                    ordinal_property.domain.append(Weakness)
                    ordinal_property.range.append(Weakness)
                    inverse_ordinal_property = types.new_class(
                        inverse_ordinal_property_name, (hasRelationshipWith,)
                    )
                    inverse_ordinal_property.domain.append(Weakness)
                    inverse_ordinal_property.range.append(Weakness)
                    ordinal_property.inverse_property = inverse_ordinal_property
                    getattr(weakness_individual, ordianl_property_name).append(
                        related_weakness_individual
                    )

                if inverse_property_name is not None:
                    inverse_property = types.new_class(
                        inverse_property_name, (hasRelationshipWith,)
                    )
                    inverse_property.domain.append(Weakness)
                    inverse_property.range.append(Weakness)
                    new_property.inverse_property = inverse_property

                if transistive_property_name is not None:
                    transistive_property = types.new_class(
                        transistive_property_name,
                        (
                            hasRelationshipWith,
                            TransitiveProperty,
                        ),
                    )
                    transistive_property.domain.append(Weakness)
                    transistive_property.range.append(Weakness)
                    transistive_range = getattr(
                        weakness_individual, transistive_property_name
                    )
                    transistive_range.append(related_weakness_individual)
                    if transistive_inverse_property_name is not None:
                        transistive_inverse_property = types.new_class(
                            transistive_inverse_property_name,
                            (
                                hasRelationshipWith,
                                TransitiveProperty,
                            ),
                        )
                        transistive_inverse_property.domain.append(Weakness)
                        transistive_inverse_property.range.append(Weakness)
                        transistive_property.inverse_property = (
                            transistive_inverse_property
                        )
                        getattr(
                            related_weakness_individual,
                            transistive_inverse_property_name,
                        ).append(weakness_individual)

# sync_reasoner()
# Why can't save inferred relations as a file, especially inverse relations?

onto.save(file="cwe.owl", format="rdfxml")
