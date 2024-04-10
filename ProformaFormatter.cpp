#include <iostream>
#include <string>
#include <map>
#include "pugixml.hpp"
#include <vector>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <regex>
#include <fstream>
#include <zip.h>
#include <unistd.h>
#include <curl/curl.h>
#include <unordered_map>
#include <cmath>
#include <filesystem>
#include <magic.h>
#include <numeric>

#ifndef PROFORMA
#define PROFORMA

const char *PROFORMA_TASK_XML_NAMESPACES[] = {"urn:proforma:v2.1"};

constexpr const char *PROFORMA_MERGED_FEEDBACK_TYPE = "merged-test-feedback";
constexpr const char *PROFORMA_SEPARATE_FEEDBACK_TYPE = "separate-test-feedback";
constexpr const char *PROFORMA_RESULT_SPEC_FORMAT_ZIP = "zip";
constexpr const char *PROFORMA_RESULT_SPEC_FORMAT_XML = "xml";
constexpr const char *PROFORMA_FEEDBACK_LEVEL_ERROR = "error";
constexpr const char *PROFORMA_FEEDBACK_LEVEL_WARNING = "warn";
constexpr const char *PROFORMA_FEEDBACK_LEVEL_INFO = "info";
constexpr const char *PROFORMA_FEEDBACK_LEVEL_DEBUG = "debug";
constexpr const char *PROFORMA_FEEDBACK_LEVEL_NOTSPECIFIED = "notspecified";

#endif /* PROFORMA */

class Util
{
public:
    static std::string getCurrentDateTime()
    {

        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);

        std::tm tm;
        gmtime_r(&time, &tm); // gmtime_r is used to get UTC time

        // Create a time string in the desired format
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");

        // Get milliseconds
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
        oss << "." << std::setfill('0') << std::setw(3) << milliseconds;

        // Get the time zone offset
        oss << "+02:00";

        return oss.str();
    }

    static std::string getFileExtension(const std::string fileName)
    {
        size_t dotPosition = fileName.find_last_of('.');
        return fileName.substr(dotPosition + 1);
    }

    /**
     * This method reads out variables from the envrionment_variables.sh script provided by vpl that are needed for the grading process.
     * Reading the values of the variables like this allows for easy expansion later when the hybrid approach is to be implemented.
     */
    static int getArgsFromVplEnvironmentScript(std::string &moodleUserId, std::string &moodleCourseId, 
        std::string &moodleURL, double &vplGradeMax)
    {
        std::ifstream environmentFile("vpl_environment.sh");

        // Check if the file is open
        if (environmentFile.is_open())
        {
            std::string line;

            // Read each line in the file
            while (getline(environmentFile, line))
            {
                size_t moodleUserIdPos = line.find("export MOODLE_USER_ID=");
                size_t moodleCourseIdPos = line.find("export MOODLE_COURSE_ID=");
                size_t moodleURLPos = line.find("export MOODLE_URL=");
                size_t vplGradeMaxPos = line.find("export VPL_GRADEMAX=");
                

                if (moodleUserIdPos != std::string::npos) {
                    moodleUserId = line.substr(moodleUserIdPos + strlen("export MOODLE_USER_ID=") + 1);
                    moodleUserId.pop_back(); // Remove the trailing double quote
                } else if (moodleCourseIdPos != std::string::npos) {
                    moodleCourseId = line.substr(moodleCourseIdPos + strlen("export MOODLE_COURSE_ID=") + 1);
                    moodleCourseId.pop_back();
                } else if (moodleURLPos != std::string::npos) {
                    moodleURL = line.substr(moodleURLPos + strlen("export MOODLE_URL=") + 1);
                    moodleURL.pop_back(); 
                } else if (vplGradeMaxPos != std::string::npos) {
                    std::string maxGrade = line.substr(vplGradeMaxPos + strlen("export VPL_GRADEMAX=") + 1);
                    maxGrade.pop_back();
                    vplGradeMax = std::stoi(maxGrade);
                } 
            }
            environmentFile.close();
        }
        else
        {
            std::cerr << "Error opening file: vpl_environment.sh" << std::endl;
            return 1;
        }

        return 0;
    }

    /**
     * This method is necessary because some graders, like GraFlap, always reutrn in xml format, overriding the user settings.
     * This method checks the first 4 bytes of the passed data parameter and compares them with the first 4 bytes expected from a zipped stream.
     */
    static bool isZipFile(const std::string &data)
    {
        // Check if the first four bytes match the ZIP file header signature
        return (data.size() >= 4) &&
               (static_cast<unsigned char>(data[0]) == 0x50) &&
               (static_cast<unsigned char>(data[1]) == 0x4B) &&
               (static_cast<unsigned char>(data[2]) == 0x03) &&
               (static_cast<unsigned char>(data[3]) == 0x04);
    }

    static int getArgsFromProformaSettingsScript(std::string &serviceURL, std::string &lmsID,
                                                 std::string &lmsPassword, std::string &graderName, std::string &graderVersion, std::string &feedbackType, std::string &feedbackStructure,
                                                 std::string &studentFeedbackLevel, std::string &teacherFeedbackLevel)
    {

        std::ifstream proformaSettingsFile("proforma_settings.sh");

        if (!proformaSettingsFile.is_open())
        {
            std::cerr << "Error opening file: proforma_settings.sh" << std::endl;
            return 1;
        }

        std::map<std::string, std::string *> configValues = {
            {"SERVICE_URL", &serviceURL},
            {"LMS_ID", &lmsID},
            {"LMS_PASSWORD", &lmsPassword},
            {"GRADER_NAME", &graderName},
            {"GRADER_VERSION", &graderVersion},
            {"FEEDBACK_TYPE", &feedbackType},
            {"FEEDBACK_STRUCTURE", &feedbackStructure},
            {"STUDENT_FEEDBACK_LEVEL", &studentFeedbackLevel},
            {"TEACHER_FEEDBACK_LEVEL", &teacherFeedbackLevel}};

        std::string line;

        while (getline(proformaSettingsFile, line))
        {
            for (const auto &config : configValues)
            {
                size_t pos = line.find("export " + config.first + "=");

                if (pos != std::string::npos)
                {
                    std::string value = line.substr(pos + ("export " + config.first + "=").length() + 1);
                    value.pop_back(); // Remove the trailing double quote
                    *(config.second) = value;
                }
            }
        }

        proformaSettingsFile.close();
        return 0;
    }

    static std::string detectProformaNamespacePrefix(pugi::xml_node &root)
    {
        // Look for namespace declarations
        for (pugi::xml_attribute attr : root.attributes())
        {
            const char *attrName = attr.name();
            const char *attrValue = attr.value();
            // Check if the attribute represents a namespace declaration
            if (strncmp(attrName, "xmlns:", 6) == 0)
            {
                // Check if the namespace prefix is in the list of proforma namespaces
                for (const char *namespaceUri : PROFORMA_TASK_XML_NAMESPACES)
                {
                    if (strcmp(namespaceUri, attrValue) == 0)
                    {
                        std::string prefix = (attrName + 6);
                        prefix.push_back(':');
                        return prefix;
                    }
                }
            }
        }
        return "";
    }
};

class GradingHintsHelper
{
private:
    pugi::xml_node gradingHints;
    pugi::xml_node tests;
    std::string proformaNamespacePrefix;
    std::unordered_map<std::string, pugi::xml_node> gradingHintsCombines;

public:
    GradingHintsHelper(const pugi::xml_node &gradingHints, const pugi::xml_node &tests, const std::string &proformaNamespacePrefix)
        : gradingHints(gradingHints), tests(tests), proformaNamespacePrefix(proformaNamespacePrefix)
    {
        if (!gradingHints.empty())
        {
            for (const auto &combine : gradingHints.select_nodes((proformaNamespacePrefix + "combine").c_str()))
            {
                gradingHintsCombines[combine.node().attribute("id").value()] = combine.node();
            }
        }
    }

    // Calculates max score for the entire grading-hints element
    double calculateMaxScore()
    {
        if (!gradingHints.empty())
        {
            return calculateMaxScoreInternal(gradingHints.select_node((proformaNamespacePrefix + "root").c_str()).node());
        }
        return 1.0;
    }

    // Calculates max score starting from the current node
    double calculateMaxScore(pugi::xml_node node)
    {
        if (!gradingHints.empty())
        {
            return calculateMaxScoreInternal(node);
        }
        return 1.0;
    }

    void adjustWeights(double factor)
    {
        adjustWeightsInternal(this->gradingHints.select_node((this->proformaNamespacePrefix + "root").c_str()).node(), factor);

        auto combineNodes = gradingHints.select_nodes((this->proformaNamespacePrefix + "combine").c_str());
        for (const auto &combineNode : combineNodes)
        {
            adjustWeightsInternal(combineNode.node(), factor);
        }
    }

    bool isEmpty() const
    {
        if (gradingHints.empty())
        {
            return true;
        }
        auto root = gradingHints.select_node((this->proformaNamespacePrefix + "root").c_str()).node();
        return root.select_nodes((this->proformaNamespacePrefix + "test-ref").c_str()).empty() &&
               root.select_nodes((this->proformaNamespacePrefix + "combine-ref").c_str()).empty();
    }

private:
    double calculateMaxScoreInternal(const pugi::xml_node elem)
    {
        std::string function = elem.attribute("function").value();
        double value = 0.0;
        std::function<double(double, double)> mergefunc;

        if (function == "min")
        {
            value = std::numeric_limits<double>::max();
            mergefunc = [](double a, double b)
            { return std::min(a, b); };
        }
        else if (function == "max")
        {
            value = 0.0;
            mergefunc = [](double a, double b)
            { return std::max(a, b); };
        }
        else if (function == "sum")
        {
            mergefunc = [](double a, double b)
            { return a + b; };
        }

        auto testRefs = elem.select_nodes((this->proformaNamespacePrefix + "test-ref").c_str());
        auto combineRefs = elem.select_nodes((this->proformaNamespacePrefix + "combine-ref").c_str());

        if (testRefs.empty() && combineRefs.empty())
        {
            // root node with no children by default accumulates all test results.
            if (elem.name() == std::string("root"))
            {
                size_t countTests = this->tests.select_nodes((this->proformaNamespacePrefix + "test").c_str()).size();
                if (countTests == 0)
                {
                    // there should be tests, but if we don't have any, we assume a maximum score of 1
                    value = 1.0;
                }
                else
                {
                    for (size_t i = 0; i < countTests; ++i)
                    {
                        value = mergefunc(value, 1.0);
                    }
                }
            }
        }
        else
        {
            for (const auto &testRef : testRefs)
            {
                double weight = 1.0;
                if (!testRef.node().attribute("weight").empty())
                {
                    weight = std::stod(testRef.node().attribute("weight").value());
                }
                value = mergefunc(value, weight);
            }

            for (const auto &combineRef : combineRefs)
            {
                std::string refId = combineRef.node().attribute("ref").value();

                double maxScore = calculateMaxScoreInternal(this->gradingHintsCombines[refId]);
                double weight = 1;
                if (!combineRef.node().attribute("weight").empty())
                {
                    weight = std::stod(combineRef.node().attribute("weight").value());
                }
                value = mergefunc(value, maxScore * weight);
            }
        }

        return value;
    }
    
    void adjustWeightsInternal(pugi::xml_node elem, double factor) {
        std::string pathToNullifyConditionsNode = this->proformaNamespacePrefix + "nullify-conditions";
        std::string pathToNullifyConditionNode = this->proformaNamespacePrefix + "nullify-condition";
        
        // process test-refs    
        for (auto &testRef : elem.select_nodes((this->proformaNamespacePrefix + "test-ref").c_str())) {
            double weight = std::stod(testRef.node().attribute("weight").value());
            testRef.node().attribute("weight").set_value(weight * factor);
            
            if (testRef.node().child(pathToNullifyConditionsNode.c_str())) {
                auto nullifyConditionsNode = testRef.node().child(pathToNullifyConditionsNode.c_str());
                adjustNullifyConditions(nullifyConditionsNode, factor);
            } else if (testRef.node().child(pathToNullifyConditionNode.c_str())) {
                auto nullifyConditionNode = testRef.node().child(pathToNullifyConditionNode.c_str());
                adjustNullifyConditions(nullifyConditionNode, factor);
            }
        }
    
        // process combine-refs
        for (auto &combineRef : elem.select_nodes((this->proformaNamespacePrefix + "combine-ref").c_str())) {
            if (combineRef.node().child(pathToNullifyConditionsNode.c_str())) {
                auto nullifyConditionsNode = combineRef.node().child(pathToNullifyConditionsNode.c_str());
                adjustNullifyConditions(nullifyConditionsNode, factor);
            } else if (combineRef.node().child(pathToNullifyConditionNode.c_str())) {
                auto nullifyConditionNode = combineRef.node().child(pathToNullifyConditionNode.c_str());
                adjustNullifyConditions(nullifyConditionNode, factor);
            }
        }
    }
    
    void adjustNullifyConditions(pugi::xml_node elem, double factor) {
        std::string pathToNullifyConditionNode = this->proformaNamespacePrefix + "nullify-condition";
        if (std::strcmp(elem.name(), pathToNullifyConditionNode.c_str()) == 0) {
            bool hasCombineRef = false;
            bool hasLiteral = false;

            for (pugi::xml_node child : elem.children()) {
                std::string nodeName = child.name();
                if (nodeName == (this->proformaNamespacePrefix + "nullify-combine-ref")) {
                    hasCombineRef = true;
                } else if (nodeName == (this->proformaNamespacePrefix + "nullify-literal")) {
                    hasLiteral = true;
                }
            }
            
            // Update the value attribute if both required elements are present
            if (hasCombineRef && hasLiteral) {
                for (auto &nullifyLiteral : elem.select_nodes((this->proformaNamespacePrefix + "nullify-literal").c_str())) {
                    double value = std::stod(nullifyLiteral.node().attribute("value").value());
                    nullifyLiteral.node().attribute("value").set_value(value * factor);
                }
            }
        } else {
            for (auto &nullifyConditionNode : elem.children()) {
                adjustNullifyConditions(nullifyConditionNode, factor);
            }
        }
    }
};

class SubmissionFormatter
{
private:
    std::unique_ptr<pugi::xml_document> document;

public:
    SubmissionFormatter() : document(std::unique_ptr<pugi::xml_document>(new pugi::xml_document))
    {
    }

    std::string createSubmissionXML(std::string taskFilenameOrUUID, std::string taskRefType,
                                    std::vector<std::string> files, std::string resultFormat, std::string resultStructure,
                                    std::string studentfeedbacklevel, std::string teacherfeedbacklevel, std::string proformaNamespacePrefix,
                                    pugi::xml_node taskGradingHintsElem, pugi::xml_node taskTestElem, double maxScoreLMS, std::string lmsURL, std::string courseID, std::string userID)
    {

        pugi::xml_node declNode = document->prepend_child(pugi::node_declaration);
        declNode.append_attribute("version") = "1.0";
        declNode.append_attribute("encoding") = "UTF-8";

        pugi::xml_node submission = document->append_child((proformaNamespacePrefix + "submission").c_str());

        /**
         * Check if proformaNamespacePrefix is not empty, and if so, add a ":" to the start of the string and
         * remove the ":" from the end of the string since it is not needed for defining the namespace
         */
        std::string modifiedNamespacePrefix = "";
        if (proformaNamespacePrefix != "")
        {
            modifiedNamespacePrefix = ":" + proformaNamespacePrefix.substr(0, proformaNamespacePrefix.length() - 1);
        }
        submission.append_attribute(("xmlns" + modifiedNamespacePrefix).c_str()) = PROFORMA_TASK_XML_NAMESPACES[0];

        // Handle different taskRefTypes
        if (taskRefType == "zip" || taskRefType == "xml")
        {
            pugi::xml_node includedTaskFile = submission.append_child((proformaNamespacePrefix + "included-task-file").c_str());
            pugi::xml_node attachedFile = includedTaskFile.append_child(
                taskRefType == "zip" ? (proformaNamespacePrefix + "attached-zip-file").c_str() : (proformaNamespacePrefix + "attached-xml-file").c_str());
            attachedFile.text().set(taskFilenameOrUUID.c_str());
        }
        else if (taskRefType == "uuid")
        {
            pugi::xml_node externalTask = submission.append_child((proformaNamespacePrefix + "external-task").c_str());
            externalTask.append_attribute("uuid") = taskFilenameOrUUID.c_str();
        }
        else
        {
            throw std::invalid_argument("Unknown task ref type '" + taskRefType + "'");
        }

        // Add Grading-Hints element if merged-test-feedback is engaged
        if (resultStructure == PROFORMA_MERGED_FEEDBACK_TYPE)
        {
            GradingHintsHelper *gradingHintsHelper = new GradingHintsHelper(taskGradingHintsElem, taskTestElem, proformaNamespacePrefix);
            if (!gradingHintsHelper->isEmpty())
            {
                double maxScoreGradingHints = gradingHintsHelper->calculateMaxScore();
                if (std::abs(maxScoreGradingHints - maxScoreLMS) > 1E-5)
                {
                    gradingHintsHelper->adjustWeights(maxScoreLMS / maxScoreGradingHints);
                    submission.append_copy(taskGradingHintsElem);
                }
            }
        }
        // Handle files
        pugi::xml_node filesNode = submission.append_child((proformaNamespacePrefix + "files").c_str());
        for (const auto &fileEntry : files)
        {
            pugi::xml_node fileNode = filesNode.append_child((proformaNamespacePrefix + "file").c_str());

            // Determine mimtype of file
            magic_t magicCookie = magic_open(MAGIC_MIME_TYPE);
            magic_load(magicCookie, nullptr);
            const char *mimeType = magic_file(magicCookie, ("submission/" + fileEntry).c_str());
            if (mimeType == nullptr)
            {
                std::cerr << "Failed to determine MIME type: " << magic_error(magicCookie) << std::endl;
                continue;
            }
            fileNode.append_attribute("mimetype").set_value(mimeType);
            if (strstr(mimeType, "text/") == mimeType)
            {
                fileNode.append_child((proformaNamespacePrefix + "attached-txt-file").c_str()).text().set(fileEntry.c_str());
            }
            else
            {
                fileNode.append_child((proformaNamespacePrefix + "attached-bin-file").c_str()).text().set(fileEntry.c_str());
            }
        }

        // Handle LMS
        pugi::xml_node lmsNode = submission.append_child((proformaNamespacePrefix + "lms").c_str());
        lmsNode.append_attribute("url").set_value(lmsURL.c_str());
        lmsNode.append_child((proformaNamespacePrefix + "submission-datetime").c_str()).text().set(Util::getCurrentDateTime().c_str());
        lmsNode.append_child((proformaNamespacePrefix + "user-id").c_str()).text().set(userID.c_str());
        lmsNode.append_child((proformaNamespacePrefix + "course-id").c_str()).text().set(courseID.c_str());

        // Hanlde result-spec
        pugi::xml_node resultSpec = submission.append_child((proformaNamespacePrefix + "result-spec").c_str());
        resultSpec.append_attribute("format").set_value(resultFormat.c_str());
        resultSpec.append_attribute("structure").set_value(resultStructure.c_str());
        resultSpec.append_child((proformaNamespacePrefix + "student-feedback-level").c_str()).text().set(studentfeedbacklevel.c_str());
        resultSpec.append_child((proformaNamespacePrefix + "teacher-feedback-level").c_str()).text().set(teacherfeedbacklevel.c_str());

        // Serialize XML to a string
        std::stringstream ss;
        document->save(ss);
        // Open the file for writing
        std::ofstream file("submission.xml");

        // Check if the file was opened successfully
        if (file.is_open())
        {
            file << ss.str();
            ;
            file.close();
        }
        else
        {
            std::cerr << "Failed to open "
                      << "submission.xml"
                      << " for writing." << std::endl;
            return "";
        }
        return ss.str();
    }

    int zipSubmission(const std::string &submissionXML, const std::string taskFileNameOrUUID, std::string taskRefType, const std::vector<std::string> submissionFilesNames)
    {

        std::string outputZip = "proformasubmission.zip";

        // Create a ZIP archive
        int *errorp;
        zip_t *archive = zip_open(outputZip.c_str(), ZIP_CREATE, errorp);

        if (!archive)
        {
            zip_error_t error;
            zip_error_init_with_code(&error, *errorp);
            const char *errorString = zip_error_strerror(&error);
            std::cerr << "Error: " << errorString << std::endl;
            return 1;
        }

        // Add submission.xml to the ZIP archive
        zip_source_t *submissionXMLSource = zip_source_buffer(archive, submissionXML.c_str(), submissionXML.size(), 0);
        zip_int64_t submissionIndex = zip_file_add(archive, "submission.xml", submissionXMLSource, ZIP_FL_ENC_UTF_8);

        if (submissionIndex < 0)
        {
            std::cerr << "Failed to add submission.xml to the ZIP archive." << std::endl;
            zip_close(archive);
            return 1;
        }

        // Add the task folder (containing either a zipped or XML file)

        /**
         * must be initialized outside of if condition so that it lives till the end of this method call.
         * Reason is that its content is only written into the zip right before zip_close(archive) is called.
         */
        std::vector<char> taskFileContent;
        if (taskRefType != "uuid")
        {
            zip_int64_t taskFolderIndex = zip_dir_add(archive, "task", ZIP_FL_ENC_UTF_8);
            if (taskFolderIndex < 0)
            {
                std::cerr << "Failed to add the task folder to the ZIP archive." << std::endl;
                zip_close(archive);
                return 1;
            }

            // Open and read the content of the task file (should work either ways whether task file in a zip or xml?)
            // ToDo: include the rest of the task files when submitted task file is not a zip
            std::string fullPathToTaskFile = "task/" + taskFileNameOrUUID;

            std::ifstream taskFileStream(fullPathToTaskFile, std::ios::binary | std::ios::ate);

            // check if opening task file stream failed
            if (!taskFileStream.is_open())
            {
                std::cerr << "Failed to open task file: " << taskFileNameOrUUID << std::endl;
                zip_close(archive);
                return 1;
            }

            std::streampos fileSize = taskFileStream.tellg();
            taskFileStream.seekg(0, std::ios::beg);
            taskFileContent.resize(fileSize);
            taskFileStream.read(taskFileContent.data(), fileSize);

            // Add the task file to the ZIP archive
            zip_source_t *taskFileSource = zip_source_buffer(archive, taskFileContent.data(), taskFileContent.size(), 0);
            zip_int64_t taskFileIndex = zip_file_add(archive, fullPathToTaskFile.c_str(), taskFileSource, ZIP_FL_ENC_UTF_8);
            if (taskFileIndex < 0)
            {
                std::cerr << "Failed to add the task file to the ZIP archive." << std::endl;
                zip_close(archive);
                return 1;
            }

            // Add the submission folder and its files to the ZIP archive
            zip_int64_t submissionFolderIndex = zip_dir_add(archive, "submission", ZIP_FL_ENC_UTF_8);
            if (submissionFolderIndex < 0)
            {
                std::cerr << "Failed to add the submission folder to the ZIP archive." << std::endl;
                zip_close(archive);
                return 1;
            }
        }

        // Open and read the content of the submission files
        std::vector<std::vector<char>> fileContents;
        std::vector<zip_source_t *> submissionFilesSources;

        for (const std::string &submissionFilePath : submissionFilesNames)
        {
            std::string fullPathToSubmissionFile = "submission/" + submissionFilePath;
            std::ifstream submissionFile(fullPathToSubmissionFile, std::ios::binary | std::ios::ate);

            if (submissionFile.is_open())
            {
                // Get the size of the file
                std::streampos fileSize = submissionFile.tellg();
                submissionFile.seekg(0, std::ios::beg);

                // Resize the fileContent buffer to fit the file size
                fileContents.emplace_back(fileSize);

                // Read the file content into the buffer
                submissionFile.read(fileContents.back().data(), fileSize);

                // Create a zip_source_t from the file content
                submissionFilesSources.push_back(zip_source_buffer(archive, fileContents.back().data(), fileSize, 0));

                // Add the file to the ZIP archive
                zip_int64_t submissionFileIndex = zip_file_add(archive, fullPathToSubmissionFile.c_str(), submissionFilesSources.back(), ZIP_FL_ENC_UTF_8);

                if (submissionFileIndex < 0)
                {
                    std::cerr << "Failed to add " << submissionFilePath << " to the ZIP archive." << std::endl;
                    zip_close(archive);
                    return -1;
                }
            }
            else
            {
                std::cerr << "Failed to open file: " << submissionFilePath << std::endl;
                zip_close(archive);
                return 1;
            }
        }

        // Close the ZIP archive
        zip_close(archive);

        return 0;
    }

private:
    // Callback function to read file content
    static size_t readCallbackPostToGrappa(void *buffer, size_t size, size_t nmemb, void *userp)
    {
        FILE *file = static_cast<FILE *>(userp);
        if (file)
        {
            return fread(buffer, size, nmemb, file);
        }
        return 0;
    }

    // Callback function to write received data into a string
    static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *output)
    {
        size_t total_size = size * nmemb;
        output->append(static_cast<char *>(contents), total_size);
        return total_size;
    }

public:
    std::string postToGrappa(const std::string graderName, const std::string graderVersion, std::string async, const std::string zipFileName,
                             std::string serviceURL, std::string lmsID, std::string lmsPassword)
    {
        std::string responseData; // To store the HTTP response

        // Initialize libcurl
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            std::cerr << "Failed to initialize libcurl." << std::endl;
            return "";
        }

        // Set the target URL
        std::string url = "http://localhost:5000/grappa-webservice-2/rest/" + lmsID + "/gradeprocesses?graderName=" + graderName + "&graderVersion=" + graderVersion + "&async=" + async;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Set the POST method
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // Set the authentication credentials
        std::string credentials = lmsID + ":" + lmsPassword;
        curl_easy_setopt(curl, CURLOPT_USERPWD, credentials.c_str());

        // Set the request body (zip file)
        FILE *file = fopen(zipFileName.c_str(), "rb");
        if (!file)
        {
            std::cerr << "Failed to open the zip file." << std::endl;
            curl_easy_cleanup(curl);
            return "";
        }

        // Set the callback function to input zipfile into the body of http post request
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallbackPostToGrappa);
        curl_easy_setopt(curl, CURLOPT_READDATA, file);

        // Set the callback function to capture the output
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);

        // Set the Content-Type header
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform the request
        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            std::cerr << "Failed to perform the request: " << curl_easy_strerror(res) << std::endl;
            return "";
        }

        // Cleanup
        fclose(file);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return responseData;
    }

    pugi::xml_document getTaskXMLContent(std::string taskfilename, std::string taskreftype)
    {
        pugi::xml_document doc;
        if (taskreftype == "zip")
        {
            int err;
            std::string zipFilePath = "task/" + taskfilename;
            zip_t *archive;
            if ((archive = zip_open(zipFilePath.c_str(), ZIP_RDONLY, &err)) == NULL)
            {
                zip_error_t error;
                zip_error_init_with_code(&error, err);
                fprintf(stderr, "%s: cannot open zip archive '%s': %s\n",
                        "SubmissionBuilder", zipFilePath.c_str(), zip_error_strerror(&error));
                zip_error_fini(&error);
            }

            zip_int64_t numEntries = zip_get_num_entries(archive, ZIP_FL_UNCHANGED);
            for (zip_int64_t i = 0; i < numEntries; ++i)
            {
                struct zip_stat fileStat;
                if (zip_stat_index(archive, i, ZIP_FL_UNCHANGED, &fileStat) == 0)
                {
                    if (std::string(fileStat.name) == "task.xml")
                    {
                        zip_file_t *file = zip_fopen_index(archive, i, ZIP_FL_UNCHANGED);
                        if (file)
                        {
                            char* buffer = new char[fileStat.size];
                            zip_fread(file, buffer, fileStat.size);
                            doc.load_string(buffer);
                            zip_fclose(file);
                            zip_close(archive);
                            delete[] buffer;
                            break;
                        }
                    }
                }
            }
        }
        else if (taskreftype == "xml")
        {
            std::string xmlFilePath = "task/" + taskfilename;
            std::ifstream xmlFile(xmlFilePath);
            if (xmlFile.is_open())
            {
                std::ostringstream buffer;
                buffer << xmlFile.rdbuf();
                doc.load_string(buffer.str().c_str());
                xmlFile.close();
            }
            else
            {
                std::cerr << "Error opening XML file: " << xmlFilePath << std::endl;
            }
        }
        return doc;
    }

    std::string getTaskFileUUID(pugi::xml_document &doc, std::string proformaNamespacePrefix)
    {
        return doc.child((proformaNamespacePrefix + "task").c_str()).attribute("uuid").value();
    }

    bool isTaskCached(std::string &taskFileUUID, std::string &serviceURL, std::string &lmsID, std::string &lmsPassword)
    {
        std::string url = serviceURL + "tasks/" + taskFileUUID;

        CURL *curl = curl_easy_init();
        if (curl)
        {
            CURLcode res;

            // Set the authentication credentials
            std::string credentials = lmsID + ":" + lmsPassword;
            curl_easy_setopt(curl, CURLOPT_USERPWD, credentials.c_str());

            // Set URL
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

            // Set the HEAD method
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

            res = curl_easy_perform(curl);

            if (res == CURLE_OK)
            {
                long responseCode;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
                if (responseCode == 200)
                {
                    // Task is cached
                    return true;
                }
                else if (responseCode == 404)
                {
                    // Task is not cached
                }
                else
                {
                    // Error occurred
                    std::cerr << "Error: " << curl_easy_strerror(res) << std::endl;
                }
            }
            else
            {
                // Curl error
                std::cerr << "Curl error: " << curl_easy_strerror(res) << std::endl;
                exit(EXIT_FAILURE);
            }

            curl_easy_cleanup(curl);
        }
        return false;
    }
};

enum NodeType
{
    TestNodeType,
    CombineNodeType
};

class GradingNode
{
public:
    std::string refId;
    NodeType type;
    std::string title;
    std::string description;
    std::string internalDescription;

    double weight;
    double rawScore;
    double maxScore;
    double actualScore;

    int indentLevel;

    // For nullify conditions
    bool nullified = false;
    std::string nullifyReason;

public:
    GradingNode(std::string refId, NodeType type, std::string title, std::string description,
                std::string internalDescription, double weight, double rawScore, double maxScore, double actualScore,
                int indentLevel) : refId{refId}, type{type}, title{title}, description{description},
                                   internalDescription{internalDescription}, weight{weight}, rawScore{rawScore}, maxScore{maxScore},
                                   actualScore{actualScore}, indentLevel{indentLevel}
    {
    }

    // Virtual destructor
    virtual ~GradingNode() = default;
};

class TestNode : public GradingNode
{
public:
    std::string subRefId;
    std::vector<std::string> studentFeedback;
    std::vector<std::string> teacherFeedback;

public:
    TestNode(std::string refId, NodeType type, std::string title, std::string description,
             std::string internalDescription, double weight, double rawScore, double maxScore, double actualScore,
             int indentLevel, std::string subRefId, std::vector<std::string> studentFeedback,
             std::vector<std::string> teacherFeedback) : GradingNode{refId, type, title, description, internalDescription, weight, 
                                                         rawScore, maxScore, actualScore, indentLevel},
                                                         subRefId{subRefId},
                                                         studentFeedback{studentFeedback}, teacherFeedback{teacherFeedback}
    {
    }
};

class CombineNode : public GradingNode
{
public:
    std::string function;
    std::vector<GradingNode *> children;
    /* This attribute indicates whether the children of the "combine" node have undergone 
    nullification checks, and subsequently, whether the score of the parent node has been adjusted accordingly. */
    bool nullificationChecked = false;

public:
    CombineNode(std::string refId, NodeType type, std::string title, std::string description,
                std::string internalDescription, double weight, double rawScore, double maxScore, double actualScore,
                int indentLevel, std::string function, std::vector<GradingNode *> children) : 
                GradingNode{refId, type, title, description, internalDescription, weight, rawScore, maxScore, actualScore, indentLevel},
                function{function}, children{children}
    {
    }

    ~CombineNode()
    {
        for (auto &ptr : children)
        {
            delete ptr;
        }
    }
};

class ProformaResponseFormatter
{
private:
    std::unique_ptr<pugi::xml_document> document;
    std::string proformaNamespaceTaskPrefix;
    std::string proformaNamespaceResponsePrefix;
    std::string feedbackType;
    pugi::xml_node gradingHintsElement;
    pugi::xml_node testsElement;
    const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

public:
    ProformaResponseFormatter(std::string responseData, std::string proformaNamespaceTaskPrefix,
                             pugi::xml_node gradingHintsElement, pugi::xml_node testsElement) : document(std::make_unique<pugi::xml_document>())
    {
        this->proformaNamespaceTaskPrefix = proformaNamespaceTaskPrefix;
        this->gradingHintsElement = gradingHintsElement;
        this->testsElement = testsElement;
        pugi::xml_parse_result result = document->load_string(responseData.c_str());

        if (!result)
        {
            std::cerr << "XML parsing error: " << result.description() << std::endl;
        }

        pugi::xml_node rootResponse = document->document_element();
        this->proformaNamespaceResponsePrefix = Util::detectProformaNamespacePrefix(rootResponse);

        this->feedbackType = this->detectFeedbackTypeFromResponse();
    }

    void processResult(double maxScoreLMS)
    {
        std::cout << "<|--" << std::endl;
        std::cout << "━━━━ EVALUATION REPORT ━━━━\n"
                  << std::endl;
        std::cout << "--|>" << std::endl;
        std::cout << "<|--" << std::endl;
        std::cout << "-To access the grading results, please follow the following steps:\n";
        std::cout << "1. Triple-click the text provided below to select it fully.\n";
        std::cout << "2. Right-click the selected text and choose \"Copy,\" or simply press `Ctrl+C` on your keyboard to copy the text.\n";
        std::cout << "3. Navigate to your web browser and focus on the URL bar at the top. You can do this by clicking on the URL bar or pressing `Ctrl+L` on your keyboard.\n";
        std::cout << "4. Right-click inside the URL bar and select \"Paste,\" or press `Ctrl+V` on your keyboard to paste the previously copied text.\n";
        std::cout << "5. Press `Enter` to navigate to the link and view your grading results.\n\n";
        std::cout << "-Text to copy:\n";
        std::cout << "--|>" << std::endl;

        if (this->feedbackType == "merged-test-feedback")
        {

            std::string grade = getGradeFromProformaResult();

            // Fetch student feedback
            std::string pathToStudentFeedbackNode = "//" + this->proformaNamespaceResponsePrefix + "response/" + this->proformaNamespaceResponsePrefix +
                                                    "merged-test-feedback/" + this->proformaNamespaceResponsePrefix + "student-feedback";
            pugi::xml_node studentFeedbackNode = document->select_node(pathToStudentFeedbackNode.c_str()).node();

            // Fetch teacher feedback
            std::string pathToTeacherFeedbackNode = "//" + this->proformaNamespaceResponsePrefix + "response/" + this->proformaNamespaceResponsePrefix +
                                                    "merged-test-feedback/" + this->proformaNamespaceResponsePrefix + "teacher-feedback";

            pugi::xml_node teacherFeedbackNode = document->select_node(pathToTeacherFeedbackNode.c_str()).node();

            std::cout << "///////////////////////////////" << std::endl;
            std::cout << "/// Student feedback //////////" << std::endl;
            std::cout << "///////////////////////////////" << std::endl;
            std::cout << "<|--" << std::endl;
            std::cout << "data:text/html;base64," << base64_encode(studentFeedbackNode.child_value()) << std::endl;
            std::cout << "--|>" << std::endl;

            std::cout << "///////////////////////////////" << std::endl;
            std::cout << "/// Teacher feedback //////////" << std::endl;
            std::cout << "///////////////////////////////" << std::endl;
            std::cout << "data:text/html;base64," << base64_encode(teacherFeedbackNode.child_value()) << std::endl;

            std::cout << "Grade :=>>" << grade << std::endl;
        }
        else
        {

            std::string pathToSeparateTestFeedbackNode = "//" + this->proformaNamespaceResponsePrefix + "response/" + this->proformaNamespaceResponsePrefix +
                                                         "separate-test-feedback";
            pugi::xml_node separateTestFeedbackNode = document->select_node(pathToSeparateTestFeedbackNode.c_str()).node();
            createResponseHTML(separateTestFeedbackNode, maxScoreLMS);
        }
    }

private:
    std::string getGradeFromProformaResult()
    {

        std::string pathToScoreNode = "//" + this->proformaNamespaceResponsePrefix + "response/" + this->proformaNamespaceResponsePrefix +
                                      "merged-test-feedback/" + this->proformaNamespaceResponsePrefix + "overall-result/" + this->proformaNamespaceResponsePrefix + "score";

        // Find the "score" element
        pugi::xml_node scoreNode = document->select_node(pathToScoreNode.c_str()).node();

        if (!scoreNode)
        {
            std::cerr << "Unable to find the 'score' element in the XML." << std::endl;
            return ""; // or throw an exception
        }

        std::string scoreValue = scoreNode.child_value();

        return scoreValue;
    }

    /**
     * This method reads out the feedback type out of the response.xml and stores it in an attribute for later use.
     * This is necessary, because some graders override the feedback type chosen by the user
     * (Example: GraFlap only has support for separate-test-feedback and always returns that feedback type regardless of the user setting)
     */
    std::string detectFeedbackTypeFromResponse()
    {

        std::string pathToResponseNode = "//" + this->proformaNamespaceResponsePrefix + "response";
        pugi::xml_node responseNode = this->document->select_node(pathToResponseNode.c_str()).node();
        std::string feedbackType = responseNode.first_child().name();

        // Check if the feedbackTypeWithPrefix string starts with the proformaPrefix
        if (feedbackType.compare(0, this->proformaNamespaceResponsePrefix.length(), this->proformaNamespaceResponsePrefix) == 0)
        {
            return feedbackType.substr(this->proformaNamespaceResponsePrefix.length());
        }
        return feedbackType;
    }

    std::string base64_encode(const std::string &input)
    {
        std::string encoded_string;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        for (char const &c : input)
        {
            char_array_3[i++] = c;
            if (i == 3)
            {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                {
                    encoded_string += base64_chars[char_array_4[i]];
                }
                i = 0;
            }
        }

        if (i > 0)
        {
            for (j = i; j < 3; j++)
            {
                char_array_3[j] = '\0';
            }

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (j = 0; (j < i + 1); j++)
            {
                encoded_string += base64_chars[char_array_4[j]];
            }

            while ((i++ < 3))
            {
                encoded_string += '=';
            }
        }

        return encoded_string;
    }

    pugi::xml_node findCombineNodeById(const std::string &refId)
    {
        // Search for a combine node with the matching id attribute
        std::string pathToRootNode = this->proformaNamespaceTaskPrefix + "combine";
        for (auto &combineNode : this->gradingHintsElement.children(pathToRootNode.c_str()))
        {
            if (combineNode.attribute("id").value() == refId)
            {
                return combineNode;
            }
        }
        // If no matching node is found, return an empty node
        return pugi::xml_node();
    }

    void createResponseHTML(pugi::xml_node separateTestFeedbackElement, double maxScoreLMS)
    {
        // Two streams. One for teacher feedback. One for student feedback.
        std::ostringstream htmlStream;
        std::ostringstream studentStream;

        // Start the HTML document
        htmlStream << "<!DOCTYPE html>\n";
        htmlStream << "<html lang='en'>\n";
        htmlStream << "<head>\n";
        htmlStream << "<meta charset='UTF-8'>\n";
        htmlStream << "<title>Evaluation Report</title>\n";
        htmlStream << "<style>\n";
        htmlStream << "h1, h2 { color: navy; margin-bottom: 0; }\n";
        htmlStream << "h3 { font-style: italic;}\n";
        htmlStream << ".feedback, .teacher-feedback { margin-bottom: 5; }\n";
        htmlStream << ".grading-node {padding-left: 1px; padding-bottom: 1px;}\n";
        htmlStream << ".indent-0 { margin-left: 0px; background-color: #b0b0b0}\n";
        htmlStream << ".indent-1 { margin-left: 20px; background-color: #c0c0c0;}\n";
        htmlStream << ".indent-2 { margin-left: 40px; background-color: #d0d0d0;}\n";
        htmlStream << ".indent-3 { margin-left: 60px; background-color: #e0e0e0;}\n";
        htmlStream << ".indent-4 { margin-left: 80px; background-color: #f0f0f0;}\n";
        htmlStream << ".indent-5 { margin-left: 100px; background-color: #f9f9f9;}\n";
        htmlStream << ".collapsible {\n";
        htmlStream << "  cursor: pointer;\n";
        htmlStream << "  padding: 10px;\n";
        htmlStream << "  width: 100%;\n";
        htmlStream << "  border: none;\n";
        htmlStream << "  text-align: left;\n";
        htmlStream << "  outline: none;\n";
        htmlStream << "  font-size: 15px;\n";
        htmlStream << "}\n\n";
        htmlStream << ".active, .collapsible:hover {\n";
        htmlStream << "  background-color: #555;\n";
        htmlStream << "}\n\n";
        htmlStream << ".content {\n";
        htmlStream << "  padding: 0 18px;\n";
        htmlStream << "  display: none;\n";
        htmlStream << "  overflow: hidden;\n";
        htmlStream << "}\n";
        htmlStream << ".nullify-reason {color: red; font-style: italic;}\n";
        htmlStream << "</style>\n";
        htmlStream << "<script>\n";
        htmlStream << "document.addEventListener(\"DOMContentLoaded\", function() {\n";
        htmlStream << "  var coll = document.getElementsByClassName(\"collapsible\");\n";
        htmlStream << "  var i;\n\n";

        htmlStream << "  for (i = 0; i < coll.length; i++) {\n";
        htmlStream << "    coll[i].addEventListener(\"click\", function() {\n";
        htmlStream << "      this.classList.toggle(\"active\");\n";
        htmlStream << "      var content = this.nextElementSibling;\n";
        htmlStream << "      if (content.style.display === \"block\") {\n";
        htmlStream << "        content.style.display = \"none\";\n";
        htmlStream << "      } else {\n";
        htmlStream << "        content.style.display = \"block\";\n";
        htmlStream << "      }\n";
        htmlStream << "    });\n";
        htmlStream << "  }\n";
        htmlStream << "});\n";
        htmlStream << "</script>\n";
        htmlStream << "</head>\n";
        htmlStream << "<body>\n";

        // Add a header for summarized feedback
        htmlStream << "<button class='collapsible'><h1>Summarized Feedback</h1></button>\n";
        htmlStream << "<div class='content'>\n";

        // Add headers for student and teacher feedback
        htmlStream << "<h2>Feedback</h2>\n";
        htmlStream << "<div class='feedback'>\n";

        // spares extra lines
        studentStream << htmlStream.str();

        // Path to nodes
        std::string pathToSubmissionFeedbackListElement = this->proformaNamespaceResponsePrefix + "submission-feedback-list";
        std::string pathToStudentFeedbackElement = this->proformaNamespaceResponsePrefix + "student-feedback";
        std::string pathToTeacherFeedbackElement = this->proformaNamespaceResponsePrefix + "teacher-feedback";
        std::string pathToContentElement = this->proformaNamespaceResponsePrefix + "content";

        // Iterate over student-feedback elements
        for (auto &studentFeedback : separateTestFeedbackElement.child(pathToSubmissionFeedbackListElement.c_str()).children(pathToStudentFeedbackElement.c_str()))
        {
            // Get the raw HTML content as a string
            std::string rawHtml = studentFeedback.child(pathToContentElement.c_str()).child_value();

            htmlStream << rawHtml << std::endl;
            studentStream << rawHtml << std::endl;
        }

        htmlStream << "</div>\n";    // Close feedback div
        studentStream << "</div>\n"; // Close feedback div

        // Add teacher feedback
        htmlStream << "<h2>Teacher Feedback</h2>\n";
        htmlStream << "<div class='teacher-feedback'>\n";

        // Iterate over teacher-feedback elements
        for (auto &teacherFeedback : separateTestFeedbackElement.child(pathToSubmissionFeedbackListElement.c_str()).children(pathToTeacherFeedbackElement.c_str()))
        {
            // Get the raw HTML content as a string
            std::string rawHtml = teacherFeedback.child(pathToContentElement.c_str()).child_value();

            htmlStream << rawHtml << std::endl;
        }

        htmlStream << "</div>\n";    // Close teacher-feedback div
        htmlStream << "</div>\n";    // close content div
        studentStream << "</div>\n"; // close content div

        // Add a header for detailed feedback
        htmlStream << "<button class='collapsible'><h1>Detailed Feedback</h1></button>\n";
        studentStream << "<button class='collapsible'><h1>Detailed Feedback</h1></button>\n";
        htmlStream << "<div class='content'>\n";
        studentStream << "<div class='content'>\n";

        std::string pathToTestsResponseNode = this->proformaNamespaceResponsePrefix + "tests-response";
        pugi::xml_node testsResponseNode = separateTestFeedbackElement.child(pathToTestsResponseNode.c_str());

        // Adjust the weights in the grading-hints element
        double scaleFactor = 1;
        GradingHintsHelper *gradingHintsHelper = new GradingHintsHelper(this->gradingHintsElement, this->testsElement, this->proformaNamespaceTaskPrefix);
        if (!gradingHintsHelper->isEmpty())
        {
            double maxScoreGradingHints = gradingHintsHelper->calculateMaxScore();
            if (std::abs(maxScoreGradingHints - maxScoreLMS) > 1E-5)
            {
                scaleFactor = maxScoreLMS / maxScoreGradingHints;
            }
        }

        // Root element in grading-hints
        std::string pathToRootNode = this->proformaNamespaceTaskPrefix + "root";
        pugi::xml_node rootNode = this->gradingHintsElement.child(pathToRootNode.c_str());

        // Scores of all the tests and sub-tests
        std::map<std::string, std::map<std::string, double>> scoresMap = processAllTestScores(testsResponseNode);

        // All the nodes in the grading-hints processed and the scores for all the levels of the tree are calculated and stored
        CombineNode *rootProcessed = processGradingNode(rootNode, testsResponseNode, scoresMap, 1, gradingHintsHelper, 0);

        // Nullify nodes according to nullify conditions
        processNullifyConditions(rootNode, rootProcessed);
        updateScoreOfCombineNode(rootProcessed);

        // Append the detailed feedback result to the htmlStream object
        double finalScore = outputGradingNode(rootProcessed, scaleFactor, htmlStream, studentStream);

        htmlStream << "</div>\n";    // close content div
        studentStream << "</div>\n"; // close content div

        // Close the HTML document
        htmlStream << "</body>\n";
        studentStream << "</body>\n";
        htmlStream << "</html>\n";
        studentStream << "</html>\n";

        // Output the encoded student feedback document
        std::cout << "///////////////////////////////" << std::endl;
        std::cout << "/// Student feedback //////////" << std::endl;
        std::cout << "///////////////////////////////" << std::endl;
        std::cout << "<|--" << std::endl;
        std::cout << "data:text/html;base64," << base64_encode(studentStream.str()) << std::endl;
        std::cout << "--|>" << std::endl;

        // Output the encoded teacher feedback document
        std::cout << "///////////////////////////////" << std::endl;
        std::cout << "/// Teacher feedback //////////" << std::endl;
        std::cout << "///////////////////////////////" << std::endl;
        std::cout << "data:text/html;base64," << base64_encode(htmlStream.str()) << std::endl;

        std::cout << "Grade :=>>" << finalScore << std::endl;

        // free resources
        delete gradingHintsHelper;
        gradingHintsHelper = nullptr;
        delete rootProcessed;
        rootProcessed = nullptr;
    }

    // A helper function to traverse "tests-response" and store scores in a map
    std::map<std::string, std::map<std::string, double>> processAllTestScores(pugi::xml_node testsResponse)
    {
        std::map<std::string, std::map<std::string, double>> scoresMap;
        for (auto &testResponse : testsResponse.children())
        {
            std::string testId = testResponse.attribute("id").value();
            std::string pathToScoreNode = this->proformaNamespaceResponsePrefix + "test-result/" +
                                          this->proformaNamespaceResponsePrefix + "result/" + this->proformaNamespaceResponsePrefix + "score";
            std::string pathToIsInternalErrorNode = this->proformaNamespaceResponsePrefix + "test-result/" +
                                                    this->proformaNamespaceResponsePrefix + "result/" + this->proformaNamespaceResponsePrefix + "is-internal-error";
            // Check if there are subtests
            auto subTestsResponseNode = testResponse.child((proformaNamespaceResponsePrefix + "subtests-response").c_str());
            if (!subTestsResponseNode)
            {
                double testScore = testResponse.select_node(pathToScoreNode.c_str()).node().text().as_double();
                bool isInternalError = testResponse.select_node(pathToIsInternalErrorNode.c_str()).node().text().as_bool();
                if (isInternalError)
                {
                    std::cerr << "One of the test results returned is invalid (Internal Error)." << std::endl;
                    std::exit(EXIT_FAILURE);
                }
                // No subtests, store the score with empty subtest id
                scoresMap[testId][""] = testScore;
            }
            else
            {
                // Iterate through subtests
                for (auto &subTestResponse : subTestsResponseNode.children())
                {
                    std::string subTestId = subTestResponse.attribute("id").value();
                    double subTestScore = subTestResponse.select_node(pathToScoreNode.c_str()).node().text().as_double();
                    bool isInternalError = subTestResponse.select_node(pathToIsInternalErrorNode.c_str()).node().text().as_bool();
                    if (isInternalError)
                    {
                        std::cerr << "One of the test results returned is invalid (Internal Error)." << std::endl;
                        std::exit(EXIT_FAILURE);
                    }
                    scoresMap[testId][subTestId] = subTestScore;
                }
            }
        }

        return scoresMap;
    }

    /**
     * Process all nodes in the grading-hints element to include all the information needed to generate an evaluation
     * report in data classes created specifically to store all the information together.
     * The evaluation report isn't generated directly because nullifying conditions must be evaluated first
     */
    CombineNode *processGradingNode(pugi::xml_node node, pugi::xml_node testsResponse, std::map<std::string, std::map<std::string, double>> scoresMap,
                                    double weight, GradingHintsHelper *gradingHintsHelper, int indentLevel)
    {
        std::string refId = node.attribute("id").as_string("root"); // default to root if not specified
        std::string title = node.child_value((this->proformaNamespaceTaskPrefix + "title").c_str());
        if (title.empty()) {
            title = refId;
        }
        std::string description = node.child_value((this->proformaNamespaceTaskPrefix + "description").c_str());
        std::string internalDescription = node.child_value((this->proformaNamespaceTaskPrefix + "internal-description").c_str());
        std::string function = node.attribute("function").as_string("min"); // default to min if not specified (ProFormA spec)
        double rawScore = 0.0;
        double maxScore = gradingHintsHelper->calculateMaxScore(node) * weight;

        if ((this->proformaNamespaceTaskPrefix + "root") == node.name())
        {
            title = "Overall result";
        }

        std::vector<double> childScores;
        std::vector<GradingNode *> processedChildren;
        std::string pathToTestRefNode = this->proformaNamespaceTaskPrefix + "test-ref";
        std::string pathToCombineRefNode = this->proformaNamespaceTaskPrefix + "combine-ref";
        for (auto &child : node.children())
        {
            std::string refId;
            std::string subRefId;
            std::string title;
            std::string description;
            std::string internalDescription;
            double weight;
            double rawScore;
            double actualScore;
            std::vector<std::string> studentFeedback;
            std::vector<std::string> teacherFeedback;
            
            if (strcmp(child.name(), pathToTestRefNode.c_str()) == 0)
            {
                refId = child.attribute("ref").value();
                subRefId = child.attribute("sub-ref").value();

                // fetch title and description of the test-ref element
                title = child.child_value((this->proformaNamespaceTaskPrefix + "title").c_str());
                description = child.child_value((this->proformaNamespaceTaskPrefix + "description").c_str());
                internalDescription = child.child_value((this->proformaNamespaceTaskPrefix + "internal-description").c_str());

                // If title or description are empty, fetch them from the corresponding test element
                if (title.empty() || description.empty())
                {
                    // Find the corresponding test by refId in the tests element
                    for (auto &test : this->testsElement.children())
                    {
                        if (std::string(test.attribute("id").value()) == refId)
                        {
                            if (title.empty()) {
                                std::string testTitle = test.child_value((this->proformaNamespaceTaskPrefix + "title").c_str());
                                if (!testTitle.empty()) {
                                    title = testTitle;
                                    if (!subRefId.empty()) {
                                        title += " (" + subRefId + ")";
                                    }   
                                }
                            }
                            if (description.empty()) {
                                std::string testDescription = test.child_value((this->proformaNamespaceTaskPrefix + "description").c_str());
                                if (!description.empty()) {
                                    description = testDescription;
                                    if (!subRefId.empty()) {
                                        description += " (" + subRefId + ")";
                                    }
                                }
                            }
                            break;
                        }
                    }
                }

                if (title.empty()) {
                    if (!subRefId.empty()) {
                        title = refId + " (" + subRefId + ")";
                    } else {
                        title = refId;
                    }
                }

                weight = std::stod(child.attribute("weight").value());
                rawScore = scoresMap[refId][subRefId]; // unsafe? should probably check if first value was found.
                actualScore = rawScore * weight;

                processTestFeedback(studentFeedback, teacherFeedback, testsResponse, refId, subRefId);

                childScores.push_back(actualScore);
                processedChildren.push_back(new TestNode{refId, NodeType::TestNodeType, title, description, 
                    internalDescription, weight, rawScore, weight, actualScore, indentLevel + 1, subRefId, studentFeedback, teacherFeedback});
            }
            else if (strcmp(child.name(), pathToCombineRefNode.c_str()) == 0)
            {
                std::string refId = child.attribute("ref").value();
                pugi::xml_node combineNode = findCombineNodeById(refId);

                double weight = 1;
                std::string weightStr = child.attribute("weight").value();
                if (!weightStr.empty())
                {
                    weight = std::stod(child.attribute("weight").value());
                }
                CombineNode *processedCombineNode = processGradingNode(combineNode, testsResponse, scoresMap, weight, 
                    gradingHintsHelper, indentLevel + 1);
                childScores.push_back(processedCombineNode->actualScore);
                processedChildren.push_back(processedCombineNode);
            }
        }

        // Calculate the combined score based on the function attribute
        if (function == "sum")
        {
            rawScore = std::accumulate(childScores.begin(), childScores.end(), 0.0);
        }
        else if (function == "min")
        {
            rawScore = *std::min_element(childScores.begin(), childScores.end());
        }
        else if (function == "max")
        {
            rawScore = *std::max_element(childScores.begin(), childScores.end());
        }
        double actualScore = rawScore * weight;
        CombineNode *processedGradingNode{new CombineNode{refId, NodeType::CombineNodeType, title, description, internalDescription, weight,
            rawScore, maxScore, actualScore, indentLevel, function, processedChildren}};

        return processedGradingNode;
    }

    /**
     * Fetches the student feedback and teacher feedback from the test response element.
     */
    void processTestFeedback(std::vector<std::string> &studentFeedback, std::vector<std::string> &teacherFeedback, pugi::xml_node testsResponse,
                             const std::string &refId, const std::string &subRefId)
    {

        // Find the test-response node with the matching refId
        for (auto &testResponse : testsResponse.children((this->proformaNamespaceResponsePrefix + "test-response").c_str()))
        {
            if (testResponse.attribute("id").value() == refId)
            {
                if (subRefId.empty())
                {
                    // Path to feedbackList node
                    std::string pathToFeedbackList = this->proformaNamespaceResponsePrefix + "test-result/" + this->proformaNamespaceResponsePrefix + "feedback-list";
                    auto feedbackList = testResponse.select_node(pathToFeedbackList.c_str()).node();

                    if (feedbackList)
                    {
                        for (auto &feedback : feedbackList.children((this->proformaNamespaceResponsePrefix + "student-feedback").c_str()))
                        {
                            studentFeedback.push_back(feedback.child_value((this->proformaNamespaceResponsePrefix + "content").c_str()));
                        }
                        for (auto &feedback : feedbackList.children((this->proformaNamespaceResponsePrefix + "teacher-feedback").c_str()))
                        {
                            teacherFeedback.push_back(feedback.child_value((this->proformaNamespaceResponsePrefix + "content").c_str()));
                        }
                    }
                }
                else
                {
                    // If subRefId is not empty, we need to find the corresponding subtest-response
                    auto subTestsResponseNode = testResponse.select_node((this->proformaNamespaceResponsePrefix + "subtests-response").c_str()).node();
                    for (auto &subTestResponse : subTestsResponseNode.children())
                    {
                        if (subTestResponse.attribute("id").value() == subRefId)
                        {
                            // Path to feedbackList node
                            std::string pathToFeedbackList = this->proformaNamespaceResponsePrefix + "test-result/" + this->proformaNamespaceResponsePrefix + "feedback-list";
                            auto feedbackList = subTestResponse.select_node(pathToFeedbackList.c_str()).node();
                            if (feedbackList)
                            {
                                for (auto &feedback : feedbackList.children((this->proformaNamespaceResponsePrefix + "student-feedback").c_str()))
                                {
                                    studentFeedback.push_back(feedback.child_value((this->proformaNamespaceResponsePrefix + "content").c_str()));
                                }
                                for (auto &feedback : feedbackList.children((this->proformaNamespaceResponsePrefix + "teacher-feedback").c_str()))
                                {
                                    teacherFeedback.push_back(feedback.child_value((this->proformaNamespaceResponsePrefix + "content").c_str()));
                                }
                            }
                            break; // Break after finding the matching subtest-response
                        }
                    }
                }
                break; // Break after finding the matching test-response
            }
        }
    }

    /**
     * Output the evaluation report.
     */
    double outputGradingNode(CombineNode *node, double scaleFactor, std::ostringstream &htmlStream, std::ostringstream &studentStream)
    {
        std::string title = node->title;
        double actualScore = node->nullified ? 0 : std::round(node->actualScore * scaleFactor * 100) / 100;

        htmlStream << "<div class='grading-node indent-" << node->indentLevel << "'>\n";
        studentStream << "<div class='grading-node indent-" << node->indentLevel << "'>\n";
        htmlStream << "<h3>";
        studentStream << "<h3>";
        if (node->refId == "root")
        {
            title = "Overall result";
        }
        htmlStream << title << " [max. " << std::round(node->maxScore * scaleFactor * 100) / 100 << "] ";
        studentStream << title << " [max. " << std::round(node->maxScore * scaleFactor * 100) / 100 << "] ";
        htmlStream << "[actual score. " << actualScore << "]</h3>\n";
        studentStream << "[actual score. " << actualScore << "]</h3>\n";
        
        
        if (node->nullified)
        {
            htmlStream << "<div class='nullify-reason'>Nullified. Reason for nullification:<br>" << node->nullifyReason << "</div>\n";
            studentStream << "<div class='nullify-reason'>Nullified. Reason for nullification:<br>" << node->nullifyReason << "</div>\n";
        }
        htmlStream << "<p>" << node->description << "</p>\n";
        studentStream << "<p>" << node->description << "</p>\n";
        htmlStream << "<p>" << node->internalDescription << "</p>\n";
        htmlStream << "<p><em> Score calculation: " << node->function << " of the following sub aspects"
                   << "</em></p>\n";
        studentStream << "<p><em> Score calculation: " << node->function << " of the following sub aspects"
                      << "</em></p>\n";

        for (auto &child : node->children)
        {
            if (child->type == NodeType::TestNodeType)
            {
                TestNode *testNode = dynamic_cast<TestNode *>(child);
                double actualScore = testNode->nullified ? 0 : testNode->actualScore;

                htmlStream << "<div class='test-ref indent-" << testNode->indentLevel + 1 << "'>\n";
                studentStream << "<div class='test-ref indent-" << testNode->indentLevel + 1 << "'>\n";
                htmlStream << "<h3>" << child->title << " [max. " << std::round(testNode->maxScore * scaleFactor * 100) / 100 << "]";
                studentStream << "<h3>" << child->title << " [max. " << std::round(testNode->maxScore * scaleFactor * 100) / 100 << "]";
                htmlStream << "[raw test score. " << testNode->rawScore << "]";
                studentStream << "[raw test score. " << testNode->rawScore << "]";
                htmlStream << "[actual score. " << std::round(actualScore * scaleFactor * 100) / 100 << "]";
                studentStream << "[actual score. " << std::round(actualScore * scaleFactor * 100) / 100 << "]";
                
                if (testNode->rawScore != 0)
                {
                    htmlStream << " - correct";
                    studentStream << " - correct";
                }
                else
                {
                    htmlStream << " - wrong";
                    studentStream << " - wrong";
                }

                if ((testNode->rawScore != 0) && (testNode->nullified))
                {
                    htmlStream << " [nullified]";
                    studentStream << " [nullified]";
                }
                htmlStream << "</h3>\n";
                studentStream << "</h3>\n";
                
                if (testNode->nullified && testNode->actualScore != 0)
                {
                    htmlStream << "<div class='nullify-reason'>Nullified. Reason for nullification:<br>" << testNode->nullifyReason << "</div>\n";
                    studentStream << "<div class='nullify-reason'>Nullified. Reason for nullification:<br>" << testNode->nullifyReason << "</div>\n";
                }

                htmlStream << "<p>" << testNode->description << "</p>\n";
                studentStream << "<p>" << testNode->description << "</p>\n";
                htmlStream << "<p>" << testNode->internalDescription << "</p>\n";

                for (auto &feedback : testNode->studentFeedback)
                {
                    htmlStream << "<div class='student-feedback indent-" + std::to_string(testNode->indentLevel) + "'>\n<h4>Student Feedback</h4>\n";
                    studentStream << "<div class='student-feedback indent-" + std::to_string(testNode->indentLevel) + "'>\n<h4>Student Feedback</h4>\n";
                    htmlStream << feedback;
                    studentStream << feedback;
                    htmlStream << "\n</div>\n";
                    studentStream << "\n</div>\n";
                }
                for (auto &feedback : testNode->teacherFeedback)
                {
                    htmlStream << "<div class='teacher-feedback indent-" + std::to_string(testNode->indentLevel) + "'>\n<h4>Teacher Feedback</h4>\n";
                    htmlStream << feedback;
                    htmlStream << "\n</div>\n";
                }

                htmlStream << "</div>\n";
                studentStream << "</div>\n";
            }
            else if (child->type == NodeType::CombineNodeType)
            {
                CombineNode *combineNode = dynamic_cast<CombineNode *>(child);
                outputGradingNode(combineNode, scaleFactor, htmlStream, studentStream);
            }
        }

        htmlStream << "</div>\n";
        studentStream << "</div>\n";

        return actualScore;
    }

    void processNullifyConditions(pugi::xml_node node, CombineNode *rootProcessed)
    {
        std::string refId = node.attribute("id").as_string("root");
        CombineNode *processedNode = dynamic_cast<CombineNode *>(findNodeInProcessedStructure(rootProcessed, refId));
        
        // check if node was already processed
        if (processedNode->nullificationChecked) {
            return;
        }
        
        // Process test-ref elements
        for (auto &testRef : node.children((this->proformaNamespaceTaskPrefix + "test-ref").c_str()))
        {
            std::string refId = testRef.attribute("ref").value();
            std::string subRefId = testRef.attribute("sub-ref").value();

            GradingNode *processedNode = findNodeInProcessedStructure(rootProcessed, refId, subRefId);
            if (processedNode->rawScore != 0)
            {
                pugi::xml_node nullifyNode;
                bool result = false;
                std::string pathToNullifyConditionsNode = this->proformaNamespaceTaskPrefix + "nullify-conditions";
                std::string pathToNullifyConditionNode = this->proformaNamespaceTaskPrefix + "nullify-condition";

                if (testRef.child(pathToNullifyConditionsNode.c_str()))
                {
                    nullifyNode = testRef.child(pathToNullifyConditionsNode.c_str());
                    result = processCompositeNullifyConditions(nullifyNode, rootProcessed);
                }
                else if (testRef.child(pathToNullifyConditionNode.c_str()))
                {
                    nullifyNode = testRef.child(pathToNullifyConditionNode.c_str());
                    result = processSingleNullifyCondition(nullifyNode, rootProcessed);
                }
                if (result)
                {
                    processedNode->nullified = true;
                    std::string nullifyTitle = nullifyNode.child((this->proformaNamespaceTaskPrefix + "title").c_str()).child_value();
                    std::string nullifyDescription = nullifyNode.child((this->proformaNamespaceTaskPrefix + "description").c_str()).child_value();
                    std::string nullifyReason = nullifyTitle;
                    if (!nullifyDescription.empty())
                    {
                        nullifyReason += ":<br>" + nullifyDescription;
                    }
                    processedNode->nullifyReason = nullifyReason;
                }
            }
        }

        // Process combine-ref elements
        for (auto &combineRef : node.children((this->proformaNamespaceTaskPrefix + "combine-ref").c_str()))
        {
            std::string refId = combineRef.attribute("ref").value();
            GradingNode *processedNode = findNodeInProcessedStructure(rootProcessed, refId);
            if (processedNode->rawScore != 0)
            {
                pugi::xml_node nullifyNode;
                bool result = false;
                std::string pathToNullifyConditionsNode = this->proformaNamespaceTaskPrefix + "nullify-conditions";
                std::string pathToNullifyConditionNode = this->proformaNamespaceTaskPrefix + "nullify-condition";

                if (combineRef.child(pathToNullifyConditionsNode.c_str()))
                {
                    nullifyNode = combineRef.child(pathToNullifyConditionsNode.c_str());
                    result = processCompositeNullifyConditions(nullifyNode, rootProcessed);
                }
                else if (combineRef.child(pathToNullifyConditionNode.c_str()))
                {
                    nullifyNode = combineRef.child(pathToNullifyConditionNode.c_str());
                    result = processSingleNullifyCondition(nullifyNode, rootProcessed);
                }
                if (result)
                {
                    processedNode->nullified = true;
                    std::string nullifyTitle = nullifyNode.child((this->proformaNamespaceTaskPrefix + "title").c_str()).child_value();
                    std::string nullifyDescription = nullifyNode.child((this->proformaNamespaceTaskPrefix + "description").c_str()).child_value();
                    std::string nullifyReason = nullifyTitle;
                    if (!nullifyDescription.empty())
                    {
                        nullifyReason += ":<br>" + nullifyDescription;
                    }
                    processedNode->nullifyReason = nullifyReason;
                }
            }
            // recursivley process the combine node
            pugi::xml_node combineNode = findCombineNodeById(refId);
            processNullifyConditions(combineNode, rootProcessed);
        }

        updateScoreOfCombineNode(processedNode);
        processedNode->nullificationChecked = true;
    }

    /**
     * Process a nullify-condition element.
     */
    bool processSingleNullifyCondition(pugi::xml_node nullifyCondition, CombineNode *rootProcessed)
    {
        std::string compareOp = nullifyCondition.attribute("compare-op").value();

        double operand1 = 0, operand2 = 0;
        bool operand1Set = false, operand2Set = false;

        for (auto &child : nullifyCondition.children())
        {
            std::string childName = child.name();
            std::string pathToNullifyCombineRef = this->proformaNamespaceTaskPrefix + "nullify-combine-ref";
            std::string pathToNullifyTesteRef = this->proformaNamespaceTaskPrefix + "nullify-test-ref";
            std::string pathToNullifyLiteral = this->proformaNamespaceTaskPrefix + "nullify-literal";

            if (childName == pathToNullifyCombineRef || childName == pathToNullifyTesteRef)
            {
                std::string refId = child.attribute("ref").value();
                std::string subRefId = child.attribute("sub-ref").value();
                GradingNode *gradingNode = findNodeInProcessedStructure(rootProcessed, refId, subRefId);
                
                /* If the node is a "combine" node and the "nullificationChecked" value is false, 
                 iterate through its children first to check for nullification and subsequently reduce the score of the parent node. 
                 This is important because the score of the "combine" node that is used for comparison should always 
                 be post potential nullification of children for the comparison to be correct */
                if (childName == pathToNullifyCombineRef) {
                    CombineNode* combineGradingNode = dynamic_cast<CombineNode *>(gradingNode);
                    if (combineGradingNode->nullificationChecked == false) {
                        pugi::xml_node combineNode = findCombineNodeById(refId);
                        processNullifyConditions(combineNode, rootProcessed);
                    }
                }
                
                if (gradingNode)
                {
                    double score = gradingNode->rawScore;
                    if (!operand1Set)
                    {
                        operand1 = score;
                        operand1Set = true;
                    }
                    else
                    {
                        operand2 = score;
                        operand2Set = true;
                    }
                }
            }
            else if (childName == pathToNullifyLiteral)
            {
                double value = child.attribute("value").as_double();
                if (!operand1Set)
                {
                    operand1 = value;
                    operand1Set = true;
                }
                else
                {
                    operand2 = value;
                    operand2Set = true;
                }
            }
        }

        if (!(operand1Set && operand2Set))
        {
            return false;
        }
        // Perform comparison based on the compare-op attribute
        return compareOperands(operand1, operand2, compareOp);
    }

    bool compareOperands(double operand1, double operand2, const std::string &compareOp)
    {
        if (compareOp == "eq")
            return operand1 == operand2;
        if (compareOp == "ne")
            return operand1 != operand2;
        if (compareOp == "gt")
            return operand1 > operand2;
        if (compareOp == "ge")
            return operand1 >= operand2;
        if (compareOp == "lt")
            return operand1 < operand2;
        if (compareOp == "le")
            return operand1 <= operand2;
        return false;
    }

    /**
     * Process a nullify-conditions element
     */
    bool processCompositeNullifyConditions(pugi::xml_node nullifyConditions, CombineNode *rootProcessed)
    {
        std::string compareOp = nullifyConditions.attribute("compose-op").value();
        std::vector<bool> results;

        std::string pathToNullifyConditionsNode = this->proformaNamespaceTaskPrefix + "nullify-conditions";
        std::string pathToNullifyConditionNode = this->proformaNamespaceTaskPrefix + "nullify-condition";

        for (auto &nullifyNode : nullifyConditions.children())
        {
            std::string nodeName = nullifyNode.name();
            bool result = false;

            if (nodeName == pathToNullifyConditionsNode)
            {
                result = processCompositeNullifyConditions(nullifyNode, rootProcessed);
            }
            else if (nodeName == pathToNullifyConditionNode)
            {
                result = processSingleNullifyCondition(nullifyNode, rootProcessed);
            }
            results.push_back(result);
        }

        if (compareOp == "and")
        {
            return std::all_of(results.begin(), results.end(), [](bool result)
                               { return result; });
        }
        else if (compareOp == "or")
        {
            return std::any_of(results.begin(), results.end(), [](bool result)
                               { return result; });
        }
        else
        {
            return false;
        }
    }

    /**
     * Findes the GradingNode that corresponds with the refId and the subRefId provided.
     */
    GradingNode *findNodeInProcessedStructure(GradingNode *currentNode, const std::string &refId, const std::string &subRefId = "")
    {
        if (currentNode->refId == refId)
        {
            if (currentNode->type == NodeType::TestNodeType)
            {
                TestNode *testNode = dynamic_cast<TestNode *>(currentNode);
                if (!subRefId.empty() && testNode->subRefId == subRefId)
                {
                    return testNode; // Match found with specific subRefId
                }
                else if (subRefId.empty())
                {
                    return testNode; // Match found without needing to check subRefId
                }
            }
            else if (currentNode->type == NodeType::CombineNodeType)
            {
                return currentNode;
            }
        }

        // If the current node is a CombineNode, iterate through its children
        if (currentNode->type == NodeType::CombineNodeType)
        {
            CombineNode *combineNode = dynamic_cast<CombineNode *>(currentNode);
            for (GradingNode *child : combineNode->children)
            {
                GradingNode *foundNode = findNodeInProcessedStructure(child, refId, subRefId);
                if (foundNode) {
                    return foundNode;
                }
            }
        }
        return nullptr;
    }
    
    void updateScoreOfCombineNode(CombineNode* combineNode) {
        double sum = 0.0;
        std::vector<double> childrenScores;
        
        for (GradingNode* child : combineNode->children) {
            if (!child->nullified) {
                childrenScores.push_back(child->actualScore);
            }
        }
        
        if (combineNode->function == "sum")
        {
            sum = std::accumulate(childrenScores.begin(), childrenScores.end(), 0.0);
        }
        else if (combineNode->function == "min")
        {
            sum = *std::min_element(childrenScores.begin(), childrenScores.end());
        }
        else if (combineNode->function == "max")
        {
            sum = *std::max_element(childrenScores.begin(), childrenScores.end());
        }
        
        combineNode->rawScore = sum;
        combineNode->actualScore = (sum * combineNode->weight);
    }

};

int main(int argc, char *argv[])
{

    // Process command-line arguments
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " 'submission file list' 'task file name'" << std::endl;
        return 1;
    }

    // Submission file list
    std::vector<std::string> submission_files_names;
    for (int i = 1; i < argc - 1; i++)
    {
        submission_files_names.push_back(argv[i]);
    }

    // User-ID and max grade from vpl_evaluate.sh
    std::string userId;
    std::string courseId;
    double maxScoreLMS;
    std::string lmsURL;

    Util::getArgsFromVplEnvironmentScript(userId, courseId, lmsURL, maxScoreLMS);

    // ProFormA task file name and extension
    std::string taskfilename = argv[argc - 1];
    std::string taskreftype = Util::getFileExtension(taskfilename);
    
    // Graders settings
    std::string serviceURL;
    std::string lmsID;
    std::string lmsPassword;
    std::string graderName;
    std::string graderVersion;
    std::string async = "false";

    // Submission settings
    std::string feedbackType;
    std::string feedbackStructure;
    std::string studentFeedbackLevel;
    std::string teacherFeedbackLevel;

    if (Util::getArgsFromProformaSettingsScript(serviceURL, lmsID, lmsPassword, graderName,graderVersion, 
        feedbackType, feedbackStructure, studentFeedbackLevel, teacherFeedbackLevel) != 0) {
        std::cerr << "Failed to open proforma_settings.sh" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// Start building submission ///////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////

    SubmissionFormatter *submissionFormatter = new SubmissionFormatter();

    // Get pugixml document of the task.xml file
    pugi::xml_document taskXMLDocument = submissionFormatter->getTaskXMLContent(taskfilename, taskreftype);

    /**
     * Load the task.xml namespace, tests and grading-hints elements.
     * They will be needed for creating the submission.xml if merged-test-feedback is engaged.
    */
    pugi::xml_node root = taskXMLDocument.document_element();
    std::string proformaNamespaceTaskPrefix = Util::detectProformaNamespacePrefix(root);
    pugi::xml_node taskGradingHintsElem = root.child((proformaNamespaceTaskPrefix + "grading-hints").c_str());
    pugi::xml_node taskTestElem = root.child((proformaNamespaceTaskPrefix + "tests").c_str());

    // Get the task UUID
    std::string taskFileUUID = submissionFormatter->getTaskFileUUID(taskXMLDocument, proformaNamespaceTaskPrefix);

    if (taskFileUUID.empty()) {
        std::cerr << "Failed to create ProFormA submission: task.xml file is either missing or activity is incorrectly configured.\n";
        std::cerr << "1. Make sure task file is included in a 'task/' directory in the execution files.\n";
        std::cerr << "2. Make sure task.xml is directly included in the task folder either as a zip or xml.\n";
        std::cerr << "3. Make sure the task is marked as non-removable under the 'File to keep when running' tab." << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Check if the task is cached on Grappa and if so, don't include in the submission (comment out when trying to debug the system to avoid caching).
    if (submissionFormatter->isTaskCached(taskFileUUID, serviceURL, lmsID, lmsPassword))
    {
        taskfilename = taskFileUUID;
        taskreftype = "uuid";
    }
    
    // Create submission.xml file
    std::string submissionXMLContent = submissionFormatter->createSubmissionXML(taskfilename, taskreftype, submission_files_names, feedbackStructure, feedbackType,
                                                                                studentFeedbackLevel, teacherFeedbackLevel, proformaNamespaceTaskPrefix, taskGradingHintsElem, taskTestElem, maxScoreLMS, lmsURL, courseId, userId);

    // Create ProFormA submission zip
    if (submissionFormatter->zipSubmission(submissionXMLContent, taskfilename, taskreftype, submission_files_names) == 1)
    {
        std::cerr << "Failed to create ProFormA submission" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Place HTTP Request to Grappa
    std::string responseData = submissionFormatter->postToGrappa(graderName, graderVersion, async, "proformasubmission.zip", serviceURL, lmsID, lmsPassword);

    //////////////////////////////////////////////////////////////////////////////////////////
    //// Start formating response ///////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////

    if (async == "true")
    {
        // TODO?
        // Pole the grappa endpoint that gives back the submission and store the result in the gradingResult variable
    }

    if (feedbackStructure == "zip" && Util::isZipFile(responseData))
    {
        std::string responseXmlFromZip;

        // Initialize libzip
        zip_error_t ziperror;
        zip_t *archive = zip_open_from_source(zip_source_buffer_create(responseData.data(), responseData.size(), 0, 0), ZIP_RDONLY, &ziperror);

        if (!archive)
        {
            std::cerr << "Failed to initialize libzip. Error code: " << zip_error_code_zip(&ziperror) << std::endl;
            zip_error_fini(&ziperror);
            return 1;
        }

        // Iterate through the files in the zip archive
        zip_int64_t num_entries = zip_get_num_entries(archive, 0);
        for (zip_int64_t i = 0; i < num_entries; ++i)
        {
            // Get information about the file in the archive
            struct zip_stat file_stat;
            if (zip_stat_index(archive, i, 0, &file_stat) == 0)
            {
                // Extract and print the content of "response.xml"
                if (std::string(file_stat.name) == "response.xml")
                {
                    zip_file_t *file = zip_fopen_index(archive, i, 0);
                    if (file)
                    {
                        char buffer[1024];
                        zip_int64_t bytesRead = zip_fread(file, buffer, sizeof(buffer));
                        while (bytesRead > 0)
                        {
                            responseXmlFromZip.append(buffer, static_cast<std::size_t>(bytesRead));
                            bytesRead = zip_fread(file, buffer, sizeof(buffer));
                        }
                        zip_fclose(file);
                    }
                    else
                    {
                        std::cerr << "Failed to open file in the zip archive." << std::endl;
                    }
                }
            }
        }
        // Cleanup libzip resources
        zip_close(archive);

        // transfer ownership of the string's internal buffer to responseData
        responseData = std::move(responseXmlFromZip);
    }

    ProformaResponseFormatter *proformaResponseFormatter = new ProformaResponseFormatter(responseData, proformaNamespaceTaskPrefix, taskGradingHintsElem, taskTestElem);
    proformaResponseFormatter->processResult(maxScoreLMS);

    //////////////////////////////////////////////////////////////////////////////////////////
    //// For debugging ///////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////

    /*
     for (const std::string& file : submission_files_names) {
         std::cout << "Submission File name: " << file << std::endl;
     }

     std::cout << "Task file: " << argv[2] << std::endl;

     // code to display the directory structure of proformasubmisison.zip
     const std::string zipFileName = "proformasubmission.zip";

     // Open the ZIP file for reading
     zip_t* archive4 = zip_open(zipFileName.c_str(), ZIP_RDONLY, nullptr);

     // Check if the ZIP file was opened successfully
     if (!archive4) {
         std::cerr << "Failed to open " << zipFileName << " for reading." << std::endl;
         return 1;
     }

     // Output the names of files and folders in the ZIP archive
     struct zip_stat zipStat;
     for (zip_int64_t i = 0; i < zip_get_num_entries(archive, 0); ++i) {
         zip_stat_init(&zipStat);
         zip_stat_index(archive4, i, 0, &zipStat);

         // Use zip_get_name to get the name of the entry
         const char* entryName = zip_get_name(archive4, i, 0);
         if (entryName) {
             std::cout << "Name: " << entryName << std::endl;
         }
     }

     // Close the ZIP archive
     zip_close(archive4);


     Run an "ls" command to check the current directory for the zip file
     system("ls -l");
     */

    return 0;
}
