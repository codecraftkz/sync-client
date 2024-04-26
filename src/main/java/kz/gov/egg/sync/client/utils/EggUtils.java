package kz.gov.egg.sync.client.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Objects;

import javax.xml.XMLConstants;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.experimental.UtilityClass;

@UtilityClass
public class EggUtils {

    public static XMLGregorianCalendar toXmlDateTime(OffsetDateTime dateTime) {
        if (dateTime == null) {
            dateTime = OffsetDateTime.now();
        }
        try {
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(dateTime.toString());
        } catch (DatatypeConfigurationException e) {
            throw new IllegalArgumentException("Failed to parse as XML datetime.");
        }
    }

    public static XMLGregorianCalendar obtainCurrentXmlDateTime() {
        return toXmlDateTime(null);
    }
    
    @Deprecated
    /**
     * @deprecated Use {@link #marshal(String, Object, Class...)} instead.
     */
    public static String marshal(Class c, Object o, String qname) {
        return marshal(qname, o, c);
    }

    public static String marshal(String qname, Object o, Class... c) {
        try (var sw = new StringWriter()) {
            if (Arrays.stream(c).anyMatch(Objects::isNull) || Objects.isNull(o)) {
                throw new IllegalArgumentException("JAXB classes or object not provided");
            }
            var ctx = JAXBContext.newInstance(c);
            var marshaller = ctx.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            var elementName = c[0].getSimpleName();
            if (c[0].getAnnotation(XmlRootElement.class) != null) {
                var xmlRoot = (XmlRootElement) c[0].getAnnotation(XmlRootElement.class);
                elementName = xmlRoot.name();
            }
            var el = new JAXBElement<Object>(new QName(qname, elementName), c[0], o);
            marshaller.marshal(el, sw);
            return sw.toString();
        } catch (IOException | JAXBException e) {
            e.printStackTrace();
            throw new IllegalStateException(o.getClass() + " marshalling failed.");
        }
    }


    public static <T> T unmarshal(Class<T> c, String xml) {
        try {
            var ctx = JAXBContext.newInstance(c);
            var unmarshaller = ctx.createUnmarshaller();
            JAXBElement<T> element = unmarshaller.unmarshal(new StreamSource(new StringReader(xml)), c);
            return element.getValue();
        } catch (JAXBException e) {
            throw new IllegalStateException("Unmarshalling failed for " + c);
        }
    }

    public static Document parseXmlString(String xml) {
        try {
            return XMLUtils.read(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), true);
         } catch (XMLParserException e) {
            throw new IllegalArgumentException("XML-string not parsed.", e);
        }
    }
    
    public static String nodeToString(Node node) {
        try (var sw = new StringWriter()) {
            var source = new DOMSource(node);
            var result = new StreamResult(sw);

            var transFactory = TransformerFactory.newInstance();
            transFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            try {
                transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            } catch (IllegalArgumentException ex) {
                // ignore
            }

            var transformer = transFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.transform(source, result);
            return sw.toString();
        } catch (TransformerException | IOException e) {
            throw new IllegalStateException("Node not transformed.", e);
        }
    }
}
