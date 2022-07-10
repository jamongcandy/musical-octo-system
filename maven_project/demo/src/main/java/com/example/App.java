package com.example;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.formats.OWLXMLDocumentFormat;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.reasoner.InferenceType;
import org.semanticweb.owlapi.util.*;

import openllet.owlapi.OpenlletReasoner;
import openllet.owlapi.OpenlletReasonerFactory;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws Exception {

        long startTime = System.nanoTime();
        OWLOntologyManager manager = OWLManager.createOWLOntologyManager();
        OWLOntology ontology = manager
                .loadOntologyFromOntologyDocument(new File(args[0]));

        File file = new File(args[1]);
        file.createNewFile();
        IRI destination = IRI.create(file);

        manager.saveOntology(ontology, new OWLXMLDocumentFormat(), destination);

        OpenlletReasoner reasoner = OpenlletReasonerFactory.getInstance().createReasoner(ontology);
        reasoner.precomputeInferences(
                InferenceType.CLASS_HIERARCHY,
                InferenceType.OBJECT_PROPERTY_HIERARCHY,
                InferenceType.DATA_PROPERTY_HIERARCHY,
                InferenceType.CLASS_ASSERTIONS,
                InferenceType.OBJECT_PROPERTY_ASSERTIONS,
                InferenceType.DATA_PROPERTY_ASSERTIONS,
                InferenceType.SAME_INDIVIDUAL,
                InferenceType.DIFFERENT_INDIVIDUALS,
                InferenceType.DISJOINT_CLASSES);
        // reasoner.precomputeInferences(InferenceType.OBJECT_PROPERTY_HIERARCHY);

        List<InferredAxiomGenerator<? extends OWLAxiom>> gens = new ArrayList<InferredAxiomGenerator<? extends OWLAxiom>>();
        gens.add(new InferredClassAssertionAxiomGenerator());
        gens.add(new InferredDataPropertyCharacteristicAxiomGenerator());
        gens.add(new InferredEquivalentClassAxiomGenerator());
        gens.add(new InferredEquivalentDataPropertiesAxiomGenerator());
        gens.add(new InferredEquivalentObjectPropertyAxiomGenerator());
        gens.add(new InferredInverseObjectPropertiesAxiomGenerator());
        gens.add(new InferredObjectPropertyCharacteristicAxiomGenerator());
        gens.add(new InferredPropertyAssertionGenerator());
        gens.add(new InferredSubClassAxiomGenerator());
        gens.add(new InferredSubDataPropertyAxiomGenerator());
        gens.add(new InferredSubObjectPropertyAxiomGenerator());

        // OWLOntology infOnt = manager.createOntology();
        InferredOntologyGenerator iog = new InferredOntologyGenerator(reasoner, gens);

        // iog.fillOntology(manager.getOWLDataFactory(), infOnt);
        iog.fillOntology(manager.getOWLDataFactory(), ontology);

        // manager.saveOntology(infOnt, new OWLXMLDocumentFormat(), destination);
        manager.saveOntology(ontology, new OWLXMLDocumentFormat(), destination);

        long endTime = System.nanoTime();
        long totalTime = endTime - startTime;
        System.out.println(TimeUnit.NANOSECONDS.toSeconds(totalTime));
    }
}
