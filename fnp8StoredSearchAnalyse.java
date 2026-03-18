package fnp8util2;

// IBM FileNet P8 5.7 - jace.jar utility
// 1-file refactor v2.2
//
// Focus:
// - XML-based StoredSearch analysis
// - Extract criteria from <where> binary tree
// - Generate default bogus values for string/date
// - Allow FN_PARAM_<PropertyName> overrides
// - Attempt reflective SearchTemplateParameters construction
//
// Notes:
// - Reflection path is best-effort because JACE signatures vary by version
// - XML is treated as the authoritative source
// - JSON is ignored for execution logic

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.CDATASection;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import com.filenet.api.collection.ContentElementList;
import com.filenet.api.collection.ObjectStoreSet;
import com.filenet.api.collection.RepositoryRowSet;
import com.filenet.api.core.Connection;
import com.filenet.api.core.ContentTransfer;
import com.filenet.api.core.Domain;
import com.filenet.api.core.Factory;
import com.filenet.api.core.ObjectStore;
import com.filenet.api.property.Properties;
import com.filenet.api.property.Property;
import com.filenet.api.query.RepositoryRow;
import com.filenet.api.query.SearchSQL;
import com.filenet.api.query.SearchScope;
import com.filenet.api.query.StoredSearch;
import com.filenet.api.util.Id;
import com.filenet.api.util.UserContext;

public class FNP8 {

    public static void main(String[] args) {
        System.out.println("Starting FileNet P8 utility v2.2...");

        Config config = Config.fromEnvironment();
        config.validate();

        if (config.disableSslVerification) {
            SkipSSLVerification.disable();
        }

        try (FileNetSession session = FileNetSession.open(config)) {
            session.printConnectionInfo();

            if (config.listObjectStores) {
                session.printObjectStores();
            }

            ObjectStore objectStore = session.fetchObjectStore(config.objectStoreName);

            if (config.listStoredSearches) {
                StoredSearchService.listStoredSearches(objectStore);
            }

            StoredSearch storedSearch = resolveStoredSearch(objectStore, config);
            if (storedSearch == null) {
                System.out.println("Geen StoredSearch gevonden.");
                return;
            }

            StoredSearchService.printStoredSearchDetails(storedSearch);

            String xmlContent = StoredSearchService.extractStoredSearchXmlContent(storedSearch);
            if (config.printStoredSearchContent) {
                StoredSearchService.printStoredSearchContent(xmlContent);
            }

            if (isBlank(xmlContent)) {
                System.out.println("Geen XML search template content gevonden.");
                return;
            }

            SearchTemplateModel model = SearchTemplateXmlParser.parse(xmlContent);
            model.applyEnvOverrides(config.dynamicParameterValues);
            model.applyBogusDefaults();
            model.printReport();

            if (config.executeStoredSearch) {
                try {
                    RepositoryRowSet results = StoredSearchService.executeStoredSearchWithParametersReflection(
                            objectStore,
                            storedSearch,
                            model,
                            config.pageSize
                    );
                    ResultPrinter.printAsTabSeparated(results);
                } catch (Exception e) {
                    System.out.println("\nUitvoeren met SearchTemplateParameters via reflection faalde:");
                    System.out.println(e.getMessage());

                    System.out.println("\nDiagnostiek:");
                    ReflectionDiagnostics.printRelevantQueryMethods();

                    System.out.println("\nDe XML-parameters zijn wel succesvol geëxtraheerd.");
                    System.out.println("Controleer welke query/template classes werkelijk aanwezig zijn in jouw jace.jar.");
                }
            }

        } catch (Exception e) {
            System.err.println("FOUT: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static StoredSearch resolveStoredSearch(ObjectStore objectStore, Config config) {
        if (!isBlank(config.storedSearchId)) {
            return StoredSearchService.findStoredSearchById(objectStore, config.storedSearchId);
        }

        if (!isBlank(config.storedSearchName)) {
            return StoredSearchService.findStoredSearchByName(objectStore, config.storedSearchName);
        }

        if (!isBlank(config.storedSearchDocumentTitle)) {
            return StoredSearchService.findStoredSearchByDocumentTitle(objectStore, config.storedSearchDocumentTitle);
        }

        return null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String safeString(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static String readAllAsUtf8(InputStream inputStream) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        int read;

        while ((read = inputStream.read(data)) != -1) {
            buffer.write(data, 0, read);
        }

        return buffer.toString(StandardCharsets.UTF_8.name());
    }

    private static String escapeSqlLiteral(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("'", "''");
    }

    private static class Config {
        private static final String DEFAULT_STANZA = "FileNetP8WSI";
        private static final String DEFAULT_OS = "OS01";
        private static final String DEFAULT_SEARCH_TITLE = "ZO4 Elwin OK";
        private static final int DEFAULT_PAGE_SIZE = 50;

        private final String uri;
        private final String username;
        private final String password;
        private final String stanza;

        private final String objectStoreName;

        private final String storedSearchId;
        private final String storedSearchName;
        private final String storedSearchDocumentTitle;

        private final boolean listObjectStores;
        private final boolean listStoredSearches;
        private final boolean printStoredSearchContent;
        private final boolean executeStoredSearch;
        private final boolean disableSslVerification;

        private final int pageSize;
        private final Map<String, String> dynamicParameterValues;

        private Config(
                String uri,
                String username,
                String password,
                String stanza,
                String objectStoreName,
                String storedSearchId,
                String storedSearchName,
                String storedSearchDocumentTitle,
                boolean listObjectStores,
                boolean listStoredSearches,
                boolean printStoredSearchContent,
                boolean executeStoredSearch,
                boolean disableSslVerification,
                int pageSize,
                Map<String, String> dynamicParameterValues) {

            this.uri = uri;
            this.username = username;
            this.password = password;
            this.stanza = stanza;
            this.objectStoreName = objectStoreName;
            this.storedSearchId = storedSearchId;
            this.storedSearchName = storedSearchName;
            this.storedSearchDocumentTitle = storedSearchDocumentTitle;
            this.listObjectStores = listObjectStores;
            this.listStoredSearches = listStoredSearches;
            this.printStoredSearchContent = printStoredSearchContent;
            this.executeStoredSearch = executeStoredSearch;
            this.disableSslVerification = disableSslVerification;
            this.pageSize = pageSize;
            this.dynamicParameterValues = dynamicParameterValues;
        }

        static Config fromEnvironment() {
            return new Config(
                    env("FN_URI"),
                    env("FN_USER"),
                    env("FN_PASS"),
                    envOrDefault("FN_STANZA", DEFAULT_STANZA),
                    envOrDefault("FN_OS", DEFAULT_OS),
                    env("FN_SEARCH_ID"),
                    env("FN_SEARCH_NAME"),
                    envOrDefault("FN_SEARCH_TITLE", DEFAULT_SEARCH_TITLE),
                    envBoolean("FN_LIST_OS", true),
                    envBoolean("FN_LIST_SEARCHES", true),
                    envBoolean("FN_PRINT_SEARCH_CONTENT", true),
                    envBoolean("FN_EXECUTE_SEARCH", true),
                    envBoolean("FN_DISABLE_SSL_VERIFICATION", false),
                    envInt("FN_PAGE_SIZE", DEFAULT_PAGE_SIZE),
                    readDynamicParametersFromEnvironment()
            );
        }

        void validate() {
            if (isBlank(uri)) {
                throw new IllegalArgumentException("FN_URI ontbreekt.");
            }
            if (isBlank(username)) {
                throw new IllegalArgumentException("FN_USER ontbreekt.");
            }
            if (password == null) {
                throw new IllegalArgumentException("FN_PASS ontbreekt.");
            }
            if (isBlank(objectStoreName)) {
                throw new IllegalArgumentException("FN_OS ontbreekt.");
            }
            if (pageSize <= 0) {
                throw new IllegalArgumentException("FN_PAGE_SIZE moet groter zijn dan 0.");
            }
        }

        private static Map<String, String> readDynamicParametersFromEnvironment() {
            Map<String, String> map = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
            Map<String, String> env = System.getenv();

            for (Map.Entry<String, String> entry : env.entrySet()) {
                String key = entry.getKey();
                if (key != null && key.startsWith("FN_PARAM_")) {
                    String paramName = key.substring("FN_PARAM_".length());
                    if (!isBlank(paramName)) {
                        map.put(paramName, entry.getValue());
                    }
                }
            }

            return map;
        }

        private static String env(String name) {
            return System.getenv(name);
        }

        private static String envOrDefault(String name, String defaultValue) {
            String value = System.getenv(name);
            return isBlank(value) ? defaultValue : value;
        }

        private static boolean envBoolean(String name, boolean defaultValue) {
            String value = System.getenv(name);
            if (isBlank(value)) {
                return defaultValue;
            }
            return "true".equalsIgnoreCase(value)
                    || "1".equalsIgnoreCase(value)
                    || "yes".equalsIgnoreCase(value)
                    || "y".equalsIgnoreCase(value);
        }

        private static int envInt(String name, int defaultValue) {
            String value = System.getenv(name);
            if (isBlank(value)) {
                return defaultValue;
            }
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Ongeldige integer voor " + name + ": " + value);
            }
        }
    }

    private static class FileNetSession implements AutoCloseable {
        private final Config config;
        private final Connection connection;
        private final Subject subject;
        private final Domain domain;
        private boolean closed = false;

        private FileNetSession(Config config, Connection connection, Subject subject, Domain domain) {
            this.config = config;
            this.connection = connection;
            this.subject = subject;
            this.domain = domain;
        }

        static FileNetSession open(Config config) {
            Connection connection = Factory.Connection.getConnection(config.uri);
            Subject subject = UserContext.createSubject(connection, config.username, config.password, config.stanza);
            UserContext.get().pushSubject(subject);
            Domain domain = Factory.Domain.fetchInstance(connection, null, null);
            return new FileNetSession(config, connection, subject, domain);
        }

        void printConnectionInfo() {
            System.out.println("Verbonden met URI: " + config.uri);
            System.out.println("Gebruiker: " + config.username);
            System.out.println("Stanza: " + config.stanza);
            System.out.println("ObjectStore: " + config.objectStoreName);
        }

        void printObjectStores() {
            System.out.println("\n--- Beschikbare Object Stores ---");
            ObjectStoreSet objectStores = domain.get_ObjectStores();
            Iterator<?> iterator = objectStores.iterator();

            while (iterator.hasNext()) {
                ObjectStore objectStore = (ObjectStore) iterator.next();
                System.out.println("ObjectStore: " + objectStore.get_DisplayName());
            }
        }

        ObjectStore fetchObjectStore(String objectStoreName) {
            ObjectStore objectStore = Factory.ObjectStore.fetchInstance(domain, objectStoreName, null);
            System.out.println("\nVerbonden met ObjectStore: " + objectStore.get_DisplayName());
            return objectStore;
        }

        @Override
        public void close() {
            if (!closed) {
                try {
                    if (subject != null) {
                        UserContext.get().popSubject();
                    }
                } catch (Exception e) {
                    System.err.println("Waarschuwing: kon UserContext niet correct afsluiten: " + e.getMessage());
                } finally {
                    closed = true;
                }
            }
        }
    }

    private static class StoredSearchService {

        static void listStoredSearches(ObjectStore objectStore) {
            System.out.println("\n--- Beschikbare Stored Searches ---");

            String query = "SELECT [Id], [Name], [DocumentTitle] FROM [StoredSearch]";
            SearchScope scope = new SearchScope(objectStore);
            RepositoryRowSet rowSet = scope.fetchRows(new SearchSQL(query), null, null, null);

            Iterator<?> iterator = rowSet.iterator();
            int count = 0;

            while (iterator.hasNext()) {
                RepositoryRow row = (RepositoryRow) iterator.next();
                String name = safeGetString(row, "Name");
                String title = safeGetString(row, "DocumentTitle");
                Id id = safeGetId(row, "Id");

                System.out.println("-> Naam: " + name + " | Titel: " + title + " | ID: " + safeString(id));
                count++;
            }

            if (count == 0) {
                System.out.println("Geen StoredSearch objecten gevonden.");
            }
        }

        static StoredSearch findStoredSearchById(ObjectStore objectStore, String id) {
            System.out.println("\nZoeken StoredSearch op ID: " + id);
            return Factory.StoredSearch.fetchInstance(objectStore, new Id(id), null);
        }

        static StoredSearch findStoredSearchByName(ObjectStore objectStore, String name) {
            System.out.println("\nZoeken StoredSearch op Name: " + name);
            return findSingleStoredSearch(objectStore,
                    "SELECT [Id] FROM [StoredSearch] WHERE [Name] = '" + escapeSqlLiteral(name) + "'");
        }

        static StoredSearch findStoredSearchByDocumentTitle(ObjectStore objectStore, String documentTitle) {
            System.out.println("\nZoeken StoredSearch op DocumentTitle: " + documentTitle);
            return findSingleStoredSearch(objectStore,
                    "SELECT [Id] FROM [StoredSearch] WHERE [DocumentTitle] = '" + escapeSqlLiteral(documentTitle) + "'");
        }

        static void printStoredSearchDetails(StoredSearch storedSearch) {
            System.out.println("\n--- StoredSearch details ---");
            System.out.println("Id: " + safeString(storedSearch.get_Id()));
            System.out.println("Name: " + safeString(storedSearch.get_Name()));
            System.out.println("DocumentTitle: " + safeString(getStringProperty(storedSearch, "DocumentTitle")));
            System.out.println("JavaClass: " + storedSearch.getClass().getName());

            try {
                ContentElementList contentElements = storedSearch.get_ContentElements();
                System.out.println("ContentElements count: " + (contentElements != null ? contentElements.size() : 0));
            } catch (Exception e) {
                System.out.println("ContentElements count: <niet beschikbaar> " + e.getMessage());
            }

            try {
                Properties props = storedSearch.getProperties();
                Iterator<?> iterator = props.iterator();

                System.out.println("\nProperties:");
                while (iterator.hasNext()) {
                    Property prop = (Property) iterator.next();
                    Object value;
                    try {
                        value = prop.getObjectValue();
                    } catch (Exception ex) {
                        value = "<niet leesbaar: " + ex.getMessage() + ">";
                    }
                    System.out.println("- " + prop.getPropertyName() + " = " + safeString(value));
                }
            } catch (Exception e) {
                System.out.println("Properties niet leesbaar: " + e.getMessage());
            }
        }

        static String extractStoredSearchXmlContent(StoredSearch storedSearch) {
            ContentElementList contentElements = storedSearch.get_ContentElements();
            if (contentElements == null || contentElements.isEmpty()) {
                return null;
            }

            Iterator<?> iterator = contentElements.iterator();

            while (iterator.hasNext()) {
                Object next = iterator.next();

                if (!(next instanceof ContentTransfer)) {
                    continue;
                }

                ContentTransfer contentTransfer = (ContentTransfer) next;
                String contentType = safeString(contentTransfer.get_ContentType());

                if (!"application/x-filenet-searchtemplate".equalsIgnoreCase(contentType)
                        && !"text/xml".equalsIgnoreCase(contentType)
                        && !"application/xml".equalsIgnoreCase(contentType)) {
                    continue;
                }

                try (InputStream inputStream = contentTransfer.accessContentStream()) {
                    return readAllAsUtf8(inputStream);
                } catch (Exception e) {
                    throw new RuntimeException("Kon XML content niet lezen", e);
                }
            }

            return null;
        }

        static void printStoredSearchContent(String xmlContent) {
            System.out.println("\n--- StoredSearch XML content dump ---");
            if (isBlank(xmlContent)) {
                System.out.println("Geen XML content aanwezig.");
                return;
            }
            System.out.println(xmlContent);
        }

        static RepositoryRowSet executeStoredSearchWithParametersReflection(
                ObjectStore objectStore,
                StoredSearch storedSearch,
                SearchTemplateModel model,
                int pageSize) throws Exception {

            System.out.println("\n--- Uitvoeren StoredSearch via reflection-based SearchTemplateParameters ---");

            SearchScope scope = new SearchScope(objectStore);

            Object searchTemplateParameters = SearchTemplateParameterReflectionBuilder.build(model);
            if (searchTemplateParameters == null) {
                throw new IllegalStateException(
                        "Kon geen SearchTemplateParameters object opbouwen via reflection. "
                        + "Waarschijnlijk ondersteunt jouw jace.jar deze query template classes niet in deze vorm."
                );
            }

            Method targetMethod = ReflectionDiagnostics.findBestFetchRowsStoredSearchMethod(scope.getClass(), searchTemplateParameters.getClass());
            if (targetMethod == null) {
                throw new NoSuchMethodException("Geen passende fetchRows methode gevonden voor StoredSearch + SearchTemplateParameters.");
            }

            System.out.println("Gevonden fetchRows methode: " + targetMethod);

            Object[] args = ReflectionDiagnostics.buildFetchRowsArguments(targetMethod, storedSearch, searchTemplateParameters, pageSize);
            Object result = targetMethod.invoke(scope, args);

            if (!(result instanceof RepositoryRowSet)) {
                throw new IllegalStateException("fetchRows gaf geen RepositoryRowSet terug maar: " + (result != null ? result.getClass().getName() : "null"));
            }

            return (RepositoryRowSet) result;
        }

        private static StoredSearch findSingleStoredSearch(ObjectStore objectStore, String query) {
            SearchScope scope = new SearchScope(objectStore);
            RepositoryRowSet result = scope.fetchRows(new SearchSQL(query), null, null, null);
            Iterator<?> iterator = result.iterator();

            if (!iterator.hasNext()) {
                return null;
            }

            RepositoryRow row = (RepositoryRow) iterator.next();
            Id id = safeGetId(row, "Id");
            if (id == null) {
                return null;
            }

            return Factory.StoredSearch.fetchInstance(objectStore, id, null);
        }

        private static String getStringProperty(StoredSearch storedSearch, String propertyName) {
            try {
                return storedSearch.getProperties().getStringValue(propertyName);
            } catch (Exception e) {
                return "";
            }
        }

        private static String safeGetString(RepositoryRow row, String propertyName) {
            try {
                return row.getProperties().getStringValue(propertyName);
            } catch (Exception e) {
                return "";
            }
        }

        private static Id safeGetId(RepositoryRow row, String propertyName) {
            try {
                return row.getProperties().getIdValue(propertyName);
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static class SearchTemplateModel {
        private String fromClassSymName;
        private final List<SearchCriterionDef> criteria = new ArrayList<SearchCriterionDef>();

        void setFromClassSymName(String fromClassSymName) {
            this.fromClassSymName = fromClassSymName;
        }

        String getFromClassSymName() {
            return fromClassSymName;
        }

        List<SearchCriterionDef> getCriteria() {
            return criteria;
        }

        void addCriterion(SearchCriterionDef def) {
            criteria.add(def);
        }

        void applyEnvOverrides(Map<String, String> overrides) {
            if (overrides == null || overrides.isEmpty()) {
                return;
            }

            for (SearchCriterionDef def : criteria) {
                String override = findOverride(overrides, def.propertyName, def.generatedParameterName);
                if (!isBlank(override)) {
                    def.chosenValue = override;
                    def.valueSource = "env";
                }
            }
        }

        void applyBogusDefaults() {
            for (SearchCriterionDef def : criteria) {
                if (!isBlank(def.chosenValue)) {
                    continue;
                }

                def.chosenValue = defaultBogusValue(def.dataType, def.operator, def.templateLiteral);
                def.valueSource = "bogus-default";
            }
        }

        void printReport() {
            System.out.println("\n--- Extracted XML Search Template Model ---");
            System.out.println("FROM class: " + safeString(fromClassSymName));
            System.out.println("Criteria count: " + criteria.size());

            int i = 1;
            for (SearchCriterionDef def : criteria) {
                System.out.println(
                        i++ + ". param=" + def.generatedParameterName
                        + " | property=" + def.propertyName
                        + " | operator=" + def.operator
                        + " | datatype=" + def.dataType
                        + " | templateLiteral=" + safeString(def.templateLiteral)
                        + " | chosenValue=" + safeString(def.chosenValue)
                        + " | source=" + safeString(def.valueSource)
                );
            }
        }

        private String findOverride(Map<String, String> overrides, String propertyName, String generatedParameterName) {
            if (overrides.containsKey(propertyName)) {
                return overrides.get(propertyName);
            }
            if (overrides.containsKey(generatedParameterName)) {
                return overrides.get(generatedParameterName);
            }

            for (Map.Entry<String, String> e : overrides.entrySet()) {
                if (e.getKey().equalsIgnoreCase(propertyName) || e.getKey().equalsIgnoreCase(generatedParameterName)) {
                    return e.getValue();
                }
            }

            return null;
        }

        private String defaultBogusValue(String datatype, String operator, String templateLiteral) {
            String dt = datatype == null ? "" : datatype.toLowerCase();
            String op = operator == null ? "" : operator.toLowerCase();

            if (dt.contains("date") || dt.contains("time") || dt.contains("timestamp")) {
                if ("gt".equals(op) || "greater".equals(op) || "greaterthan".equals(op)) {
                    return "2000-01-01T00:00:00.000+01:00";
                }
                if ("lt".equals(op) || "less".equals(op) || "lessthan".equals(op)) {
                    return "2099-12-31T00:00:00.000+01:00";
                }
                return "2025-01-01T00:00:00.000+01:00";
            }

            if (dt.contains("int") || dt.contains("long") || dt.contains("short") || dt.contains("double") || dt.contains("float") || dt.contains("decimal")) {
                return "1";
            }

            if (dt.contains("bool")) {
                return "true";
            }

            return "BOGUS_STRING";
        }
    }

    private static class SearchCriterionDef {
        private String generatedParameterName;
        private String propertyName;
        private String operator;
        private String dataType;
        private String templateLiteral;
        private String chosenValue;
        private String valueSource;
    }

    private static class SearchTemplateXmlParser {

        static SearchTemplateModel parse(String xml) {
            try {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);

                DocumentBuilder db = dbf.newDocumentBuilder();
                Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

                SearchTemplateModel model = new SearchTemplateModel();

                Element root = doc.getDocumentElement();
                Element fromClassElement = findFirstDescendantByPath(root, "searchspec", "searchcriteria", "searchclauses", "searchclause", "from", "class");
                if (fromClassElement != null) {
                    model.setFromClassSymName(attr(fromClassElement, "symname"));
                }

                Element where = findFirstDescendantByPath(root, "searchspec", "searchcriteria", "searchclauses", "searchclause", "where");
                if (where != null) {
                    Counter counter = new Counter();
                    traverseWhereTree(where, model, counter);
                }

                return model;
            } catch (Exception e) {
                throw new RuntimeException("Fout bij parsen search template XML", e);
            }
        }

        private static void traverseWhereTree(Element parent, SearchTemplateModel model, Counter counter) {
            NodeList children = parent.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                Node node = children.item(i);
                if (!(node instanceof Element)) {
                    continue;
                }

                Element child = (Element) node;
                String local = localName(child);

                if (isOperatorNode(local)) {
                    SearchCriterionDef def = buildCriterionFromOperatorNode(child, counter.next());
                    if (def != null) {
                        model.addCriterion(def);
                    }

                    traverseWhereTree(child, model, counter);
                } else {
                    traverseWhereTree(child, model, counter);
                }
            }
        }

        private static SearchCriterionDef buildCriterionFromOperatorNode(Element operatorElement, int sequence) {
            Element whereprop = findFirstChildByLocalName(operatorElement, "whereprop");
            if (whereprop == null) {
                return null;
            }

            String propertyName = attr(whereprop, "symname");
            if (isBlank(propertyName)) {
                propertyName = attr(whereprop, "name");
            }

            Element propdesc = findFirstChildByLocalName(whereprop, "propdesc");
            String dataType = propdesc != null ? attr(propdesc, "datatype") : "";

            Element literal = findFirstChildByLocalName(operatorElement, "literal");
            String literalValue = literal != null ? textContent(literal) : "";

            String operator = localName(operatorElement);

            SearchCriterionDef def = new SearchCriterionDef();
            def.propertyName = propertyName;
            def.operator = operator;
            def.dataType = dataType;
            def.templateLiteral = literalValue;
            def.generatedParameterName = buildGeneratedParameterName(propertyName, operator, sequence);

            return def;
        }

        private static String buildGeneratedParameterName(String propertyName, String operator, int sequence) {
            return safeParamToken(propertyName) + "_" + safeParamToken(operator) + "_" + sequence;
        }

        private static String safeParamToken(String value) {
            if (value == null) {
                return "x";
            }
            return value.replaceAll("[^A-Za-z0-9_]", "_");
        }

        private static boolean isOperatorNode(String local) {
            if (local == null) {
                return false;
            }

            return "eq".equalsIgnoreCase(local)
                    || "gt".equalsIgnoreCase(local)
                    || "lt".equalsIgnoreCase(local)
                    || "gte".equalsIgnoreCase(local)
                    || "lte".equalsIgnoreCase(local)
                    || "like".equalsIgnoreCase(local)
                    || "in".equalsIgnoreCase(local)
                    || "inany".equalsIgnoreCase(local)
                    || "contains".equalsIgnoreCase(local)
                    || "startswith".equalsIgnoreCase(local)
                    || "not".equalsIgnoreCase(local);
        }

        private static Element findFirstDescendantByPath(Element start, String... path) {
            Element current = start;

            if (current != null && path.length > 0 && pathEquals(current, path[0])) {
                int startIndex = 1;
                for (int i = startIndex; i < path.length; i++) {
                    current = findFirstChildByLocalName(current, path[i]);
                    if (current == null) {
                        return null;
                    }
                }
                return current;
            }

            return findFirstDescendantByPathRecursive(start, 0, path);
        }

        private static Element findFirstDescendantByPathRecursive(Element current, int pathIndex, String[] path) {
            if (current == null) {
                return null;
            }

            if (pathEquals(current, path[pathIndex])) {
                if (pathIndex == path.length - 1) {
                    return current;
                }

                NodeList children = current.getChildNodes();
                for (int i = 0; i < children.getLength(); i++) {
                    Node child = children.item(i);
                    if (child instanceof Element) {
                        Element found = findFirstDescendantByPathRecursive((Element) child, pathIndex + 1, path);
                        if (found != null) {
                            return found;
                        }
                    }
                }
            } else {
                NodeList children = current.getChildNodes();
                for (int i = 0; i < children.getLength(); i++) {
                    Node child = children.item(i);
                    if (child instanceof Element) {
                        Element found = findFirstDescendantByPathRecursive((Element) child, pathIndex, path);
                        if (found != null) {
                            return found;
                        }
                    }
                }
            }

            return null;
        }

        private static boolean pathEquals(Element element, String name) {
            String local = localName(element);
            String node = element.getNodeName();
            return name.equals(local) || name.equals(node);
        }

        private static Element findFirstChildByLocalName(Element parent, String localName) {
            NodeList children = parent.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node node = children.item(i);
                if (node instanceof Element) {
                    Element e = (Element) node;
                    if (localName.equals(localName(e)) || localName.equals(e.getNodeName())) {
                        return e;
                    }
                }
            }
            return null;
        }

        private static String localName(Node node) {
            return node.getLocalName() != null ? node.getLocalName() : node.getNodeName();
        }

        private static String attr(Element e, String name) {
            return e.hasAttribute(name) ? e.getAttribute(name) : "";
        }

        private static String textContent(Element e) {
            StringBuilder sb = new StringBuilder();
            NodeList children = e.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                if (n instanceof CDATASection || n instanceof Text) {
                    sb.append(n.getNodeValue());
                }
            }

            return sb.toString();
        }

        private static class Counter {
            private int value = 0;
            int next() {
                value++;
                return value;
            }
        }
    }

    private static class SearchTemplateParameterReflectionBuilder {

        static Object build(SearchTemplateModel model) throws Exception {
            System.out.println("\n--- Reflection build SearchTemplateParameters ---");

            ClassLoader cl = Thread.currentThread().getContextClassLoader();

            Class<?> paramsClass = tryLoad(cl,
                    "com.filenet.api.query.SearchTemplateParameters",
                    "com.filenet.api.query.SearchTemplateWhereProperties",
                    "com.filenet.api.query.SearchTemplateWhereProperty");

            if (paramsClass == null) {
                throw new ClassNotFoundException("Geen relevante SearchTemplate* class gevonden in jace.jar.");
            }

            Class<?> searchTemplateParametersClass = tryLoad(cl, "com.filenet.api.query.SearchTemplateParameters");
            Class<?> wherePropertyClass = tryLoad(cl, "com.filenet.api.query.SearchTemplateWhereProperty");
            Class<?> wherePropertyListClass = tryLoad(cl, "com.filenet.api.collection.SearchTemplateWherePropertyList");
            Class<?> factoryClass = tryLoad(cl, "com.filenet.api.core.Factory");

            System.out.println("Detected classes:");
            System.out.println("- SearchTemplateParameters: " + className(searchTemplateParametersClass));
            System.out.println("- SearchTemplateWhereProperty: " + className(wherePropertyClass));
            System.out.println("- SearchTemplateWherePropertyList: " + className(wherePropertyListClass));
            System.out.println("- Factory: " + className(factoryClass));

            if (searchTemplateParametersClass == null || wherePropertyClass == null || wherePropertyListClass == null || factoryClass == null) {
                System.out.println("Reflection binding niet mogelijk: niet alle verwachte query classes zijn aanwezig.");
                System.out.println("Detected classes:");
                System.out.println("- SearchTemplateParameters: " + className(searchTemplateParametersClass));
                System.out.println("- SearchTemplateWhereProperty: " + className(wherePropertyClass));
                System.out.println("- SearchTemplateWherePropertyList: " + className(wherePropertyListClass));
                System.out.println("- Factory: " + className(factoryClass));
                return null;
            }

            Object wherePropertyList = instantiateViaFactoryOrDirect(factoryClass, wherePropertyListClass);
            if (wherePropertyList == null) {
                throw new IllegalStateException("Kon SearchTemplateWherePropertyList niet aanmaken.");
            }

            Method addMethod = findAddMethod(wherePropertyList.getClass());
            if (addMethod == null) {
                throw new NoSuchMethodException("Geen add(...) methode gevonden op " + wherePropertyList.getClass().getName());
            }

            for (SearchCriterionDef def : model.getCriteria()) {
                Object whereProp = instantiateViaFactoryOrDirect(factoryClass, wherePropertyClass);
                if (whereProp == null) {
                    throw new IllegalStateException("Kon SearchTemplateWhereProperty niet aanmaken.");
                }

                boolean populated = populateWhereProperty(whereProp, def);
                if (!populated) {
                    throw new IllegalStateException("Kon SearchTemplateWhereProperty niet vullen voor property " + def.propertyName);
                }

                addMethod.invoke(wherePropertyList, whereProp);
            }

            Object params = instantiateViaFactoryOrDirect(factoryClass, searchTemplateParametersClass);
            if (params == null) {
                throw new IllegalStateException("Kon SearchTemplateParameters niet aanmaken.");
            }

            boolean ok = populateSearchTemplateParameters(params, model, wherePropertyList);
            if (!ok) {
                throw new IllegalStateException("Kon SearchTemplateParameters niet vullen.");
            }

            return params;
        }

        private static boolean populateSearchTemplateParameters(Object params, SearchTemplateModel model, Object wherePropertyList) {
            List<Method> methods = allMethods(params.getClass());

            boolean whereSet = false;
            boolean fromSet = false;

            for (Method m : methods) {
                String name = m.getName();
                Class<?>[] p = m.getParameterTypes();
                try {
                    if (!whereSet && ("set_WhereProperties".equals(name) || "setWhereProperties".equals(name) || "set_WherePropertyList".equals(name))
                            && p.length == 1 && p[0].isAssignableFrom(wherePropertyList.getClass())) {
                        m.invoke(params, wherePropertyList);
                        whereSet = true;
                        continue;
                    }

                    if (!fromSet && ("set_FromClass".equals(name) || "setFromClass".equals(name) || "set_FromClassName".equals(name) || "setFromClassName".equals(name))
                            && p.length == 1 && p[0] == String.class) {
                        m.invoke(params, model.getFromClassSymName());
                        fromSet = true;
                        continue;
                    }
                } catch (Exception ignore) {
                }
            }

            if (!whereSet) {
                for (Method m : methods) {
                    try {
                        if (m.getParameterTypes().length == 1
                                && m.getParameterTypes()[0].isAssignableFrom(wherePropertyList.getClass())
                                && m.getName().toLowerCase().contains("where")) {
                            m.invoke(params, wherePropertyList);
                            whereSet = true;
                            break;
                        }
                    } catch (Exception ignore) {
                    }
                }
            }

            if (!fromSet) {
                for (Method m : methods) {
                    try {
                        if (m.getParameterTypes().length == 1
                                && m.getParameterTypes()[0] == String.class
                                && m.getName().toLowerCase().contains("from")) {
                            m.invoke(params, model.getFromClassSymName());
                            fromSet = true;
                            break;
                        }
                    } catch (Exception ignore) {
                    }
                }
            }

            System.out.println("populateSearchTemplateParameters: whereSet=" + whereSet + ", fromSet=" + fromSet);
            return whereSet || fromSet;
        }

        private static boolean populateWhereProperty(Object whereProp, SearchCriterionDef def) {
            List<Method> methods = allMethods(whereProp.getClass());

            boolean nameSet = false;
            boolean valueSet = false;
            boolean operatorSet = false;
            boolean datatypeSet = false;

            for (Method m : methods) {
                String name = m.getName();
                Class<?>[] p = m.getParameterTypes();
                if (p.length != 1) {
                    continue;
                }

                try {
                    if (!nameSet && isNameSetter(name) && p[0] == String.class) {
                        m.invoke(whereProp, def.propertyName);
                        nameSet = true;
                        continue;
                    }

                    if (!valueSet && isValueSetter(name)) {
                        Object converted = convertStringToExpectedType(def.chosenValue, def.dataType, p[0]);
                        if (converted != UnsupportedValue.INSTANCE) {
                            m.invoke(whereProp, converted);
                            valueSet = true;
                            continue;
                        }
                    }

                    if (!operatorSet && isOperatorSetter(name) && p[0] == String.class) {
                        m.invoke(whereProp, normalizeOperator(def.operator));
                        operatorSet = true;
                        continue;
                    }

                    if (!datatypeSet && isDatatypeSetter(name) && p[0] == String.class) {
                        m.invoke(whereProp, def.dataType);
                        datatypeSet = true;
                        continue;
                    }
                } catch (Exception ignore) {
                }
            }

            if (!nameSet) {
                for (Method m : methods) {
                    try {
                        if (m.getParameterTypes().length == 1
                                && m.getParameterTypes()[0] == String.class
                                && m.getName().toLowerCase().contains("name")) {
                            m.invoke(whereProp, def.propertyName);
                            nameSet = true;
                            break;
                        }
                    } catch (Exception ignore) {
                    }
                }
            }

            if (!valueSet) {
                for (Method m : methods) {
                    try {
                        if (m.getParameterTypes().length == 1
                                && (m.getName().toLowerCase().contains("value") || m.getName().toLowerCase().contains("literal"))) {
                            Object converted = convertStringToExpectedType(def.chosenValue, def.dataType, m.getParameterTypes()[0]);
                            if (converted != UnsupportedValue.INSTANCE) {
                                m.invoke(whereProp, converted);
                                valueSet = true;
                                break;
                            }
                        }
                    } catch (Exception ignore) {
                    }
                }
            }

            System.out.println("populateWhereProperty[" + def.propertyName + "]: nameSet=" + nameSet
                    + ", valueSet=" + valueSet + ", operatorSet=" + operatorSet + ", datatypeSet=" + datatypeSet);

            return nameSet && valueSet;
        }

        private static boolean isNameSetter(String name) {
            String n = name.toLowerCase();
            return "set_name".equals(n)
                    || "setname".equals(n)
                    || n.contains("propertyname")
                    || n.contains("symbolicname")
                    || n.contains("symname")
                    || n.contains("name");
        }

        private static boolean isValueSetter(String name) {
            String n = name.toLowerCase();
            return "set_value".equals(n)
                    || "setvalue".equals(n)
                    || n.contains("literal")
                    || n.contains("value");
        }

        private static boolean isOperatorSetter(String name) {
            String n = name.toLowerCase();
            return n.contains("operator") || n.contains("comparison");
        }

        private static boolean isDatatypeSetter(String name) {
            String n = name.toLowerCase();
            return n.contains("datatype") || n.contains("type");
        }

        private static String normalizeOperator(String operator) {
            if (operator == null) {
                return "";
            }
            return operator.toUpperCase();
        }

        private static Object convertStringToExpectedType(String value, String declaredDatatype, Class<?> targetType) {
            try {
                if (targetType == String.class || Object.class == targetType) {
                    return value;
                }

                if (targetType == Integer.class || targetType == int.class) {
                    return Integer.valueOf(value);
                }
                if (targetType == Long.class || targetType == long.class) {
                    return Long.valueOf(value);
                }
                if (targetType == Double.class || targetType == double.class) {
                    return Double.valueOf(value);
                }
                if (targetType == Float.class || targetType == float.class) {
                    return Float.valueOf(value);
                }
                if (targetType == Boolean.class || targetType == boolean.class) {
                    return Boolean.valueOf(value);
                }

                if (targetType.isArray() && targetType.getComponentType() == String.class) {
                    Object array = Array.newInstance(String.class, 1);
                    Array.set(array, 0, value);
                    return array;
                }

                if ("java.util.Date".equals(targetType.getName())
                        || "java.sql.Timestamp".equals(targetType.getName())
                        || "java.time.Instant".equals(targetType.getName())
                        || "java.time.OffsetDateTime".equals(targetType.getName())) {
                    return tryCreateTemporalObject(targetType, value);
                }
            } catch (Exception e) {
                return UnsupportedValue.INSTANCE;
            }

            return UnsupportedValue.INSTANCE;
        }

        private static Object tryCreateTemporalObject(Class<?> targetType, String value) {
            try {
                if ("java.sql.Timestamp".equals(targetType.getName())) {
                    String normalized = value.replace('T', ' ');
                    int plus = normalized.indexOf('+');
                    if (plus > 0) {
                        normalized = normalized.substring(0, plus);
                    }
                    if (normalized.length() == 19) {
                        normalized += ".0";
                    }
                    Class<?> ts = Class.forName("java.sql.Timestamp");
                    Method valueOf = ts.getMethod("valueOf", String.class);
                    return valueOf.invoke(null, normalized);
                }

                if ("java.util.Date".equals(targetType.getName())) {
                    return new java.util.Date();
                }

                if ("java.time.Instant".equals(targetType.getName())) {
                    Class<?> instant = Class.forName("java.time.Instant");
                    Method parse = instant.getMethod("parse", String.class);
                    String iso = normalizeOffsetDateTimeToInstant(value);
                    return parse.invoke(null, iso);
                }

                if ("java.time.OffsetDateTime".equals(targetType.getName())) {
                    Class<?> odt = Class.forName("java.time.OffsetDateTime");
                    Method parse = odt.getMethod("parse", String.class);
                    return parse.invoke(null, value);
                }
            } catch (Exception ignore) {
            }

            return UnsupportedValue.INSTANCE;
        }

        private static String normalizeOffsetDateTimeToInstant(String value) {
            if (value == null) {
                return "2025-01-01T00:00:00Z";
            }
            if (value.endsWith("Z")) {
                return value;
            }
            return value.replace("+01:00", "Z").replace("+00:00", "Z");
        }

        private static Object instantiateViaFactoryOrDirect(Class<?> factoryClass, Class<?> targetClass) {
            try {
                Object viaFactory = instantiateViaFactory(factoryClass, targetClass);
                if (viaFactory != null) {
                    return viaFactory;
                }
            } catch (Exception ignore) {
            }

            try {
                return targetClass.getDeclaredConstructor().newInstance();
            } catch (Exception ignore) {
            }

            return null;
        }

        private static Object instantiateViaFactory(Class<?> factoryClass, Class<?> targetClass) throws Exception {
            for (Class<?> nested : factoryClass.getDeclaredClasses()) {
                if (nested.getSimpleName().equals(targetClass.getSimpleName())
                        || nested.getName().endsWith("." + targetClass.getSimpleName())) {
                    for (Method m : nested.getMethods()) {
                        if ((m.getName().equals("createInstance") || m.getName().equals("createList"))
                                && m.getParameterTypes().length == 0) {
                            Object obj = m.invoke(null);
                            if (obj != null && targetClass.isAssignableFrom(obj.getClass())) {
                                return obj;
                            }
                        }
                    }
                }
            }

            for (Method m : factoryClass.getMethods()) {
                if ((m.getName().equals("createInstance") || m.getName().equals("createList"))
                        && m.getParameterTypes().length == 0
                        && targetClass.isAssignableFrom(m.getReturnType())) {
                    return m.invoke(null);
                }
            }

            return null;
        }

        private static Method findAddMethod(Class<?> listClass) {
            for (Method m : listClass.getMethods()) {
                if (m.getName().equals("add") && m.getParameterTypes().length == 1) {
                    return m;
                }
            }
            return null;
        }

        private static List<Method> allMethods(Class<?> clazz) {
            List<Method> list = new ArrayList<Method>();
            for (Method m : clazz.getMethods()) {
                list.add(m);
            }
            return list;
        }

        private static Class<?> tryLoad(ClassLoader cl, String... classNames) {
            for (String name : classNames) {
                try {
                    return Class.forName(name, false, cl);
                } catch (Exception ignore) {
                }
            }
            return null;
        }

        private static String className(Class<?> clazz) {
            return clazz == null ? "<not found>" : clazz.getName();
        }

        private enum UnsupportedValue {
            INSTANCE
        }
    }

    private static class ReflectionDiagnostics {

    	static void printRelevantQueryMethods() {
    	    System.out.println("\n--- Compact reflection diagnostics ---");
    	    printFetchRowsMethods("com.filenet.api.query.SearchScope");
    	    printMatchingClasses(
    	            "com.filenet.api.query.SearchTemplateParameters",
    	            "com.filenet.api.query.SearchTemplateWhereProperty",
    	            "com.filenet.api.collection.SearchTemplateWherePropertyList",
    	            "com.filenet.api.query.SearchTemplate",
    	            "com.filenet.api.query.SearchTemplateWhereClause",
    	            "com.filenet.api.query.SearchTemplateSelectProperty",
    	            "com.filenet.api.collection.SearchTemplateSelectPropertyList"
    	    );
    	}

    	private static void printFetchRowsMethods(String className) {
    	    try {
    	        Class<?> clazz = Class.forName(className);
    	        System.out.println("\nClass: " + className);
    	        for (Method m : clazz.getMethods()) {
    	            if ("fetchRows".equals(m.getName())) {
    	                System.out.println("  " + m.toString());
    	            }
    	        }
    	    } catch (Exception e) {
    	        System.out.println("\nClass: " + className + " -> not found");
    	    }
    	}

    	private static void printMatchingClasses(String... classNames) {
    	    System.out.println("\nRelevant SearchTemplate classes:");
    	    for (String className : classNames) {
    	        try {
    	            Class<?> clazz = Class.forName(className);
    	            System.out.println("  FOUND: " + clazz.getName());
    	            printCompactMethods(clazz);
    	        } catch (Exception e) {
    	            System.out.println("  NOT FOUND: " + className);
    	        }
    	    }
    	}

    	private static void printCompactMethods(Class<?> clazz) {
    	    for (Method m : clazz.getMethods()) {
    	        if (m.getDeclaringClass() == Object.class) {
    	            continue;
    	        }

    	        String name = m.getName().toLowerCase();

    	        if (name.contains("create")
    	                || name.contains("fetch")
    	                || name.contains("set")
    	                || name.contains("get")
    	                || name.contains("add")
    	                || name.contains("where")
    	                || name.contains("value")
    	                || name.contains("name")
    	                || name.contains("class")) {
    	            System.out.println("    " + m.toString());
    	        }
    	    }
    	}
    	
        static Method findBestFetchRowsStoredSearchMethod(Class<?> scopeClass, Class<?> paramsClass) {
            Method fallback = null;

            for (Method m : scopeClass.getMethods()) {
                if (!"fetchRows".equals(m.getName())) {
                    continue;
                }

                Class<?>[] p = m.getParameterTypes();
                if (p.length < 2) {
                    continue;
                }

                boolean firstMatches = "com.filenet.api.query.StoredSearch".equals(p[0].getName());
                boolean secondMatches = p[1].isAssignableFrom(paramsClass) || p[1].getName().contains("SearchTemplate");

                if (firstMatches && secondMatches) {
                    return m;
                }

                if (firstMatches) {
                    fallback = m;
                }
            }

            return fallback;
        }

        static Object[] buildFetchRowsArguments(Method method, StoredSearch storedSearch, Object searchTemplateParameters, int pageSize) {
            Class<?>[] p = method.getParameterTypes();
            Object[] args = new Object[p.length];

            for (int i = 0; i < p.length; i++) {
                Class<?> type = p[i];
                String name = type.getName();

                if (i == 0 && "com.filenet.api.query.StoredSearch".equals(name)) {
                    args[i] = storedSearch;
                } else if (searchTemplateParameters != null && type.isAssignableFrom(searchTemplateParameters.getClass())) {
                    args[i] = searchTemplateParameters;
                } else if (type == Integer.class || type == int.class) {
                    args[i] = Integer.valueOf(pageSize);
                } else if (type == Boolean.class || type == boolean.class) {
                    args[i] = Boolean.FALSE;
                } else {
                    args[i] = null;
                }
            }

            return args;
        }

        private static void printClassMethods(String className) {
            try {
                Class<?> clazz = Class.forName(className);
                System.out.println("\nClass: " + className);
                for (Method m : clazz.getMethods()) {
                    System.out.println("  " + m.toString());
                }
            } catch (Exception e) {
                System.out.println("\nClass: " + className + " -> not found");
            }
        }

    }

    private static class ResultPrinter {

        static void printAsTabSeparated(RepositoryRowSet rowSet) {
            System.out.println("\n--- Zoekresultaten (Tab Separated) ---");

            Iterator<?> rowIterator = rowSet.iterator();
            boolean headerPrinted = false;
            int rowCount = 0;

            while (rowIterator.hasNext()) {
                RepositoryRow row = (RepositoryRow) rowIterator.next();

                if (!headerPrinted) {
                    printHeader(row);
                    headerPrinted = true;
                }

                printRow(row);
                rowCount++;
            }

            if (!headerPrinted) {
                System.out.println("Geen resultaten gevonden.");
            } else {
                System.out.println("\nAantal resultaten: " + rowCount);
            }
        }

        private static void printHeader(RepositoryRow row) {
            StringBuilder header = new StringBuilder();
            Iterator<?> propertyIterator = row.getProperties().iterator();

            while (propertyIterator.hasNext()) {
                Property property = (Property) propertyIterator.next();
                header.append(property.getPropertyName()).append("\t");
            }

            System.out.println(header.toString().trim());
        }

        private static void printRow(RepositoryRow row) {
            StringBuilder line = new StringBuilder();
            Iterator<?> propertyIterator = row.getProperties().iterator();

            while (propertyIterator.hasNext()) {
                Property property = (Property) propertyIterator.next();
                Object value;
                try {
                    value = property.getObjectValue();
                } catch (Exception e) {
                    value = "<niet leesbaar>";
                }
                line.append(value != null ? value.toString() : "").append("\t");
            }

            System.out.println(line.toString().trim());
        }
    }

    private static class SkipSSLVerification {
        static void disable() {
            try {
                TrustManager[] trustAllCerts = new TrustManager[] {
                        new X509TrustManager() {
                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }

                            @Override
                            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                            }

                            @Override
                            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                            }
                        }
                };

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustAllCerts, new SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

                HostnameVerifier allHostsValid = (hostname, session) -> true;
                HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

                System.out.println("WAARSCHUWING: SSL verificatie staat uit. Alleen voor testomgevingen.");
            } catch (Exception e) {
                throw new RuntimeException("Kon SSL verificatie niet uitschakelen.", e);
            }
        }
    }
}
