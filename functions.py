import hashlib
import json
import os
import re
import xmltodict
import html


def token_check(token):
    return True


def get_cvss_color(cvss_score):
    """ score_ranges = {
        (0, 3.9): 'green',       # Low severity, color: red
        (4.0, 6.9): 'yellow',  # Medium severity, color: orange
        (7.0, 8.9): 'orange',  # High severity, color: yellow
        (9.0, 10.0): 'red'   # Critical severity, color: green
    } """

    score_ranges = {
        (0, 3.9): 'green',  # Low severity, color: red
        (4.0, 6.9): 'yellow',  # Medium severity, color: orange
        (7.0, 10.0): 'red',  # High severity, color: yellow
    }

    try:
        cvss_score = float(cvss_score)
    except:
        return 'black', 'white'  # Return None if the cvss_score cannot be converted to a float

    # Find the appropriate color based on the cvss_score
    for score_range, color in score_ranges.items():
        if score_range[0] <= cvss_score <= score_range[1]:
            if color == "yellow":
                return color, "black"
            else:
                return color, "white"

    # Return None if the cvss_score is not within any defined range
    return 'black', 'white'


def _get_cwe_description(cwe_nr):
    cwe_descriptions = {
        'CWE-102': 'Struts: Duplicate Validation Forms',
        'CWE-103': 'Struts: Incomplete validate() Method Definition',
        'CWE-104': 'Struts: Form Bean Does Not Extend Validation Class',
        'CWE-105': 'Struts: Form Field Without Validator',
        'CWE-106': 'Struts: Plug-in Framework not in Use',
        'CWE-107': 'Struts: Unused Validation Form',
        'CWE-108': 'Struts: Unvalidated Action Form',
        'CWE-109': 'Struts: Validator Turned Off',
        'CWE-11': 'ASP.NET Misconfiguration: Creating Debug Binary',
        'CWE-110': 'Struts: Validator Without Form Field',
        'CWE-111': 'Direct Use of Unsafe JNI',
        'CWE-112': 'Missing XML Validation',
        'CWE-113': "Failure to Sanitize CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
        'CWE-114': 'Process Control',
        'CWE-115': 'Misinterpretation of Input',
        'CWE-116': 'Improper Encoding or Escaping of Output',
        'CWE-117': 'Improper Output Sanitization for Logs',
        'CWE-118': "Improper Access of Indexable Resource ('Range Error')",
        'CWE-119': 'Failure to Constrain Operations within the Bounds of a Memory Buffer',
        'CWE-12': 'ASP.NET Misconfiguration: Missing Custom Error Page',
        'CWE-120': "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        'CWE-121': 'Stack-based Buffer Overflow',
        'CWE-122': 'Heap-based Buffer Overflow',
        'CWE-123': 'Write-what-where Condition',
        'CWE-124': "Buffer Underwrite ('Buffer Underflow')",
        'CWE-125': 'Out-of-bounds Read',
        'CWE-126': 'Buffer Over-read',
        'CWE-127': 'Buffer Under-read',
        'CWE-128': 'Wrap-around Error',
        'CWE-13': 'ASP.NET Misconfiguration: Password in Configuration File',
        'CWE-130': 'Improper Handling of Length Parameter Inconsistency',
        'CWE-131': 'Incorrect Calculation of Buffer Size',
        'CWE-132': 'DEPRECATED (Duplicate): Miscalculated Null Termination',
        'CWE-134': 'Uncontrolled Format String',
        'CWE-135': 'Incorrect Calculation of Multi-Byte String Length',
        'CWE-138': 'Improper Neutralization of Special Elements',
        'CWE-14': 'Compiler Removal of Code to Clear Buffers',
        'CWE-140': 'Failure to Sanitize Delimiters',
        'CWE-141': 'Improper Neutralization of Parameter/Argument Delimiters',
        'CWE-142': 'Improper Neutralization of Value Delimiters',
        'CWE-143': 'Improper Neutralization of Record Delimiters',
        'CWE-144': 'Improper Neutralization of Line Delimiters',
        'CWE-145': 'Improper Neutralization of Section Delimiters',
        'CWE-146': 'Improper Neutralization of Expression/Command Delimiters',
        'CWE-147': 'Improper Neutralization of Input Terminators',
        'CWE-148': 'Failure to Sanitize Input Leaders',
        'CWE-149': 'Failure to Sanitize Quoting Syntax',
        'CWE-15': 'External Control of System or Configuration Setting',
        'CWE-150': 'Improper Neutralization of Escape, Meta, or Control Sequences',
        'CWE-151': 'Improper Neutralization of Comment Delimiters',
        'CWE-152': 'Improper Neutralization of Macro Symbols',
        'CWE-153': 'Improper Neutralization of Substitution Characters',
        'CWE-154': 'Improper Neutralization of Variable Name Delimiters',
        'CWE-155': 'Improper Neutralization of Wildcards or Matching Symbols',
        'CWE-156': 'Improper Neutralization of Whitespace',
        'CWE-157': 'Failure to Sanitize Paired Delimiters',
        'CWE-158': 'Improper Neutralization of Null Byte or NUL Character',
        'CWE-159': 'Failure to Sanitize Special Element',
        'CWE-160': 'Improper Neutralization of Leading Special Elements',
        'CWE-161': 'Improper Neutralization of Multiple Leading Special Elements',
        'CWE-162': 'Improper Neutralization of Trailing Special Elements',
        'CWE-163': 'Improper Neutralization of Multiple Trailing Special Elements',
        'CWE-164': 'Improper Neutralization of Internal Special Elements',
        'CWE-165': 'Improper Neutralization of Multiple Internal Special Elements',
        'CWE-166': 'Improper Handling of Missing Special Element',
        'CWE-167': 'Improper Handling of Additional Special Element',
        'CWE-168': 'Failure to Resolve Inconsistent Special Elements',
        'CWE-170': 'Improper Null Termination',
        'CWE-172': 'Encoding Error',
        'CWE-173': 'Failure to Handle Alternate Encoding',
        'CWE-174': 'Double Decoding of the Same Data',
        'CWE-175': 'Failure to Handle Mixed Encoding',
        'CWE-176': 'Failure to Handle Unicode Encoding',
        'CWE-177': 'Failure to Handle URL Encoding (Hex Encoding)',
        'CWE-178': 'Failure to Resolve Case Sensitivity',
        'CWE-179': 'Incorrect Behavior Order: Early Validation',
        'CWE-180': 'Incorrect Behavior Order: Validate Before Canonicalize',
        'CWE-181': 'Incorrect Behavior Order: Validate Before Filter',
        'CWE-182': 'Collapse of Data Into Unsafe Value',
        'CWE-183': 'Permissive Whitelist',
        'CWE-184': 'Incomplete Blacklist',
        'CWE-185': 'Incorrect Regular Expression',
        'CWE-186': 'Overly Restrictive Regular Expression',
        'CWE-187': 'Partial Comparison',
        'CWE-188': 'Reliance on Data/Memory Layout',
        'CWE-190': 'Integer Overflow or Wraparound',
        'CWE-191': 'Integer Underflow (Wrap or Wraparound)',
        'CWE-193': 'Off-by-one Error',
        'CWE-194': 'Unexpected Sign Extension',
        'CWE-195': 'Signed to Unsigned Conversion Error',
        'CWE-196': 'Unsigned to Signed Conversion Error',
        'CWE-197': 'Numeric Truncation Error',
        'CWE-198': 'Use of Incorrect Byte Ordering',
        'CWE-20': 'Improper Input Validation',
        'CWE-200': 'Information Exposure',
        'CWE-201': 'Information Leak Through Sent Data',
        'CWE-202': 'Privacy Leak through Data Queries',
        'CWE-203': 'Information Exposure Through Discrepancy',
        'CWE-204': 'Response Discrepancy Information Leak',
        'CWE-205': 'Information Exposure Through Behavioral Discrepancy',
        'CWE-206': 'Internal Behavioral Inconsistency Information Leak',
        'CWE-207': 'Information Exposure Through an External Behavioral Inconsistency',
        'CWE-208': 'Timing Discrepancy Information Leak',
        'CWE-209': 'Information Exposure Through an Error Message',
        'CWE-210': 'Product-Generated Error Message Information Leak',
        'CWE-211': 'Product-External Error Message Information Leak',
        'CWE-212': 'Improper Cross-boundary Removal of Sensitive Data',
        'CWE-213': 'Intended Information Leak',
        'CWE-214': 'Process Environment Information Leak',
        'CWE-215': 'Information Leak Through Debug Information',
        'CWE-216': 'Containment Errors (Container Errors)',
        'CWE-217': 'DEPRECATED: Failure to Protect Stored Data from Modification',
        'CWE-218': 'DEPRECATED (Duplicate): Failure to provide confidentiality for stored data',
        'CWE-219': 'Sensitive Data Under Web Root',
        'CWE-22': "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        'CWE-220': 'Sensitive Data Under FTP Root',
        'CWE-221': 'Information Loss or Omission',
        'CWE-222': 'Truncation of Security-relevant Information',
        'CWE-223': 'Omission of Security-relevant Information',
        'CWE-224': 'Obscured Security-relevant Information by Alternate Name',
        'CWE-225': 'DEPRECATED (Duplicate): General Information Management Problems',
        'CWE-226': 'Sensitive Information Uncleared Before Release',
        'CWE-227': "Failure to Fulfill API Contract ('API Abuse')",
        'CWE-228': 'Improper Handling of Syntactically Invalid Structure',
        'CWE-229': 'Improper Handling of Values',
        'CWE-23': 'Relative Path Traversal',
        'CWE-230': 'Improper Handling of Missing Values',
        'CWE-231': 'Improper Handling of Extra Values',
        'CWE-232': 'Improper Handling of Undefined Values',
        'CWE-233': 'Parameter Problems',
        'CWE-234': 'Failure to Handle Missing Parameter',
        'CWE-235': 'Improper Handling of Extra Parameters',
        'CWE-236': 'Improper Handling of Undefined Parameters',
        'CWE-237': 'Improper Handling of Structural Elements',
        'CWE-238': 'Improper Handling of Incomplete Structural Elements',
        'CWE-239': 'Failure to Handle Incomplete Element',
        'CWE-24': "Path Traversal: '../filedir'",
        'CWE-240': 'Improper Handling of Inconsistent Structural Elements',
        'CWE-241': 'Improper Handling of Unexpected Data Type',
        'CWE-242': 'Use of Inherently Dangerous Function',
        'CWE-243': 'Failure to Change Working Directory in chroot Jail',
        'CWE-244': "Failure to Clear Heap Memory Before Release ('Heap Inspection')",
        'CWE-245': 'J2EE Bad Practices: Direct Management of Connections',
        'CWE-246': 'J2EE Bad Practices: Direct Use of Sockets',
        'CWE-247': 'Reliance on DNS Lookups in a Security Decision',
        'CWE-248': 'Uncaught Exception',
        'CWE-249': 'DEPRECATED: Often Misused: Path Manipulation',
        'CWE-25': "Path Traversal: '/../filedir'",
        'CWE-250': 'Execution with Unnecessary Privileges',
        'CWE-252': 'Unchecked Return Value',
        'CWE-253': 'Incorrect Check of Function Return Value',
        'CWE-256': 'Plaintext Storage of a Password',
        'CWE-257': 'Storing Passwords in a Recoverable Format',
        'CWE-258': 'Empty Password in Configuration File',
        'CWE-259': 'Use of Hard-coded Password',
        'CWE-26': "Path Traversal: '/dir/../filename'",
        'CWE-260': 'Password in Configuration File',
        'CWE-261': 'Weak Cryptography for Passwords',
        'CWE-262': 'Not Using Password Aging',
        'CWE-263': 'Password Aging with Long Expiration',
        'CWE-266': 'Incorrect Privilege Assignment',
        'CWE-267': 'Privilege Defined With Unsafe Actions',
        'CWE-268': 'Privilege Chaining',
        'CWE-269': 'Improper Privilege Management',
        'CWE-27': "Path Traversal: 'dir/../../filename'",
        'CWE-270': 'Privilege Context Switching Error',
        'CWE-271': 'Privilege Dropping / Lowering Errors',
        'CWE-272': 'Least Privilege Violation',
        'CWE-273': 'Improper Check for Dropped Privileges',
        'CWE-274': 'Improper Handling of Insufficient Privileges',
        'CWE-276': 'Incorrect Default Permissions',
        'CWE-277': 'Insecure Inherited Permissions',
        'CWE-278': 'Insecure Preserved Inherited Permissions',
        'CWE-279': 'Incorrect Execution-Assigned Permissions',
        'CWE-28': "Path Traversal: '..\\filedir'",
        'CWE-280': 'Improper Handling of Insufficient Permissions or Privileges',
        'CWE-281': 'Improper Preservation of Permissions',
        'CWE-282': 'Improper Ownership Management',
        'CWE-283': 'Unverified Ownership',
        'CWE-284': 'Access Control (Authorization) Issues',
        'CWE-285': 'Improper Access Control (Authorization)',
        'CWE-286': 'Incorrect User Management',
        'CWE-287': 'Improper Authentication',
        'CWE-288': 'Authentication Bypass Using an Alternate Path or Channel',
        'CWE-289': 'Authentication Bypass by Alternate Name',
        'CWE-29': "Path Traversal: '\\..\\filename'",
        'CWE-290': 'Authentication Bypass by Spoofing',
        'CWE-292': 'Trusting Self-reported DNS Name',
        'CWE-293': 'Using Referer Field for Authentication',
        'CWE-294': 'Authentication Bypass by Capture-replay',
        'CWE-296': 'Improper Following of Chain of Trust for Certificate Validation',
        'CWE-297': 'Improper Validation of Host-specific Certificate Data',
        'CWE-298': 'Improper Validation of Certificate Expiration',
        'CWE-299': 'Improper Check for Certificate Revocation',
        'CWE-30': "Path Traversal: '\\dir\\..\\filename'",
        'CWE-300': "Channel Accessible by Non-Endpoint ('Man-in-the-Middle')",
        'CWE-301': 'Reflection Attack in an Authentication Protocol',
        'CWE-302': 'Authentication Bypass by Assumed-Immutable Data',
        'CWE-303': 'Incorrect Implementation of Authentication Algorithm',
        'CWE-304': 'Missing Critical Step in Authentication',
        'CWE-305': 'Authentication Bypass by Primary Weakness',
        'CWE-306': 'Missing Authentication for Critical Function',
        'CWE-307': 'Improper Restriction of Excessive Authentication Attempts',
        'CWE-308': 'Use of Single-factor Authentication',
        'CWE-309': 'Use of Password System for Primary Authentication',
        'CWE-31': "Path Traversal: 'dir\\..\\..\\filename'",
        'CWE-311': 'Missing Encryption of Sensitive Data',
        'CWE-312': 'Cleartext Storage of Sensitive Information',
        'CWE-313': 'Plaintext Storage in a File or on Disk',
        'CWE-314': 'Plaintext Storage in the Registry',
        'CWE-315': 'Plaintext Storage in a Cookie',
        'CWE-316': 'Plaintext Storage in Memory',
        'CWE-317': 'Plaintext Storage in GUI',
        'CWE-318': 'Plaintext Storage in Executable',
        'CWE-319': 'Cleartext Transmission of Sensitive Information',
        'CWE-32': "Path Traversal: '...' (Triple Dot)",
        'CWE-321': 'Use of Hard-coded Cryptographic Key',
        'CWE-322': 'Key Exchange without Entity Authentication',
        'CWE-323': 'Reusing a Nonce, Key Pair in Encryption',
        'CWE-324': 'Use of a Key Past its Expiration Date',
        'CWE-325': 'Missing Required Cryptographic Step',
        'CWE-326': 'Inadequate Encryption Strength',
        'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
        'CWE-328': 'Reversible One-Way Hash',
        'CWE-329': 'Not Using a Random IV with CBC Mode',
        'CWE-33': "Path Traversal: '....' (Multiple Dot)",
        'CWE-330': 'Use of Insufficiently Random Values',
        'CWE-331': 'Insufficient Entropy',
        'CWE-332': 'Insufficient Entropy in PRNG',
        'CWE-333': 'Improper Handling of Insufficient Entropy in TRNG',
        'CWE-334': 'Small Space of Random Values',
        'CWE-335': 'PRNG Seed Error',
        'CWE-336': 'Same Seed in PRNG',
        'CWE-337': 'Predictable Seed in PRNG',
        'CWE-338': 'Use of Cryptographically Weak PRNG',
        'CWE-339': 'Small Seed Space in PRNG',
        'CWE-34': "Path Traversal: '....//'",
        'CWE-340': 'Predictability Problems',
        'CWE-341': 'Predictable from Observable State',
        'CWE-342': 'Predictable Exact Value from Previous Values',
        'CWE-343': 'Predictable Value Range from Previous Values',
        'CWE-344': 'Use of Invariant Value in Dynamically Changing Context',
        'CWE-345': 'Insufficient Verification of Data Authenticity',
        'CWE-346': 'Origin Validation Error',
        'CWE-347': 'Improper Verification of Cryptographic Signature',
        'CWE-348': 'Use of Less Trusted Source',
        'CWE-349': 'Acceptance of Extraneous Untrusted Data With Trusted Data',
        'CWE-35': "Path Traversal: '.../...//'",
        'CWE-350': 'Improperly Trusted Reverse DNS',
        'CWE-351': 'Insufficient Type Distinction',
        'CWE-353': 'Failure to Add Integrity Check Value',
        'CWE-354': 'Improper Validation of Integrity Check Value',
        'CWE-356': 'Product UI does not Warn User of Unsafe Actions',
        'CWE-357': 'Insufficient UI Warning of Dangerous Operations',
        'CWE-358': 'Improperly Implemented Security Check for Standard',
        'CWE-359': 'Privacy Violation',
        'CWE-36': 'Absolute Path Traversal',
        'CWE-360': 'Trust of System Event Data',
        'CWE-362': 'Race Condition',
        'CWE-363': 'Race Condition Enabling Link Following',
        'CWE-364': 'Signal Handler Race Condition',
        'CWE-365': 'Race Condition in Switch',
        'CWE-366': 'Race Condition within a Thread',
        'CWE-367': 'Time-of-check Time-of-use (TOCTOU) Race Condition',
        'CWE-368': 'Context Switching Race Condition',
        'CWE-369': 'Divide By Zero',
        'CWE-37': "Path Traversal: '/absolute/pathname/here'",
        'CWE-370': 'Missing Check for Certificate Revocation after Initial Check',
        'CWE-372': 'Incomplete Internal State Distinction',
        'CWE-373': 'State Synchronization Error',
        'CWE-374': 'Mutable Objects Passed by Reference',
        'CWE-375': 'Passing Mutable Objects to an Untrusted Method',
        'CWE-377': 'Insecure Temporary File',
        'CWE-378': 'Creation of Temporary File With Insecure Permissions',
        'CWE-379': 'Creation of Temporary File in Directory with Incorrect Permissions',
        'CWE-38': "Path Traversal: '\\absolute\\pathname\\here'",
        'CWE-382': 'J2EE Bad Practices: Use of System.exit()',
        'CWE-383': 'J2EE Bad Practices: Direct Use of Threads',
        'CWE-385': 'Covert Timing Channel',
        'CWE-386': 'Symbolic Name not Mapping to Correct Object',
        'CWE-39': "Path Traversal: 'C:dirname'",
        'CWE-390': 'Detection of Error Condition Without Action',
        'CWE-391': 'Unchecked Error Condition',
        'CWE-392': 'Failure to Report Error in Status Code',
        'CWE-393': 'Return of Wrong Status Code',
        'CWE-394': 'Unexpected Status Code or Return Value',
        'CWE-395': 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
        'CWE-396': 'Declaration of Catch for Generic Exception',
        'CWE-397': 'Declaration of Throws for Generic Exception',
        'CWE-398': 'Indicator of Poor Code Quality',
        'CWE-40': "Path Traversal: '\\UNC\\share\\name\\' (Windows UNC Share)",
        'CWE-400': "Uncontrolled Resource Consumption ('Resource Exhaustion')",
        'CWE-401': "Failure to Release Memory Before Removing Last Reference ('Memory Leak')",
        'CWE-402': "Transmission of Private Resources into a New Sphere ('Resource Leak')",
        'CWE-403': 'UNIX File Descriptor Leak',
        'CWE-404': 'Improper Resource Shutdown or Release',
        'CWE-405': 'Asymmetric Resource Consumption (Amplification)',
        'CWE-406': 'Insufficient Control of Network Message Volume (Network Amplification)',
        'CWE-407': 'Algorithmic Complexity',
        'CWE-408': 'Incorrect Behavior Order: Early Amplification',
        'CWE-409': 'Improper Handling of Highly Compressed Data (Data Amplification)',
        'CWE-41': 'Improper Resolution of Path Equivalence',
        'CWE-410': 'Insufficient Resource Pool',
        'CWE-412': 'Unrestricted Externally Accessible Lock',
        'CWE-413': 'Insufficient Resource Locking',
        'CWE-414': 'Missing Lock Check',
        'CWE-415': 'Double Free',
        'CWE-416': 'Use After Free',
        'CWE-419': 'Unprotected Primary Channel',
        'CWE-42': "Path Equivalence: 'filename.' (Trailing Dot)",
        'CWE-420': 'Unprotected Alternate Channel',
        'CWE-421': 'Race Condition During Access to Alternate Channel',
        'CWE-422': "Unprotected Windows Messaging Channel ('Shatter')",
        'CWE-423': 'DEPRECATED (Duplicate): Proxied Trusted Channel',
        'CWE-424': 'Failure to Protect Alternate Path',
        'CWE-425': "Direct Request ('Forced Browsing')",
        'CWE-427': 'Uncontrolled Search Path Element',
        'CWE-428': 'Unquoted Search Path or Element',
        'CWE-43': "Path Equivalence: 'filename....' (Multiple Trailing Dot)",
        'CWE-430': 'Deployment of Wrong Handler',
        'CWE-431': 'Missing Handler',
        'CWE-432': 'Dangerous Handler not Disabled During Sensitive Operations',
        'CWE-433': 'Unparsed Raw Web Content Delivery',
        'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
        'CWE-435': 'Interaction Error',
        'CWE-436': 'Interpretation Conflict',
        'CWE-437': 'Incomplete Model of Endpoint Features',
        'CWE-439': 'Behavioral Change in New Version or Environment',
        'CWE-44': "Path Equivalence: 'file.name' (Internal Dot)",
        'CWE-440': 'Expected Behavior Violation',
        'CWE-441': 'Unintended Proxy/Intermediary',
        'CWE-443': 'DEPRECATED (Duplicate): HTTP response splitting',
        'CWE-444': "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
        'CWE-446': 'UI Discrepancy for Security Feature',
        'CWE-447': 'Unimplemented or Unsupported Feature in UI',
        'CWE-448': 'Obsolete Feature in UI',
        'CWE-449': 'The UI Performs the Wrong Action',
        'CWE-45': "Path Equivalence: 'file...name' (Multiple Internal Dot)",
        'CWE-450': 'Multiple Interpretations of UI Input',
        'CWE-451': 'UI Misrepresentation of Critical Information',
        'CWE-453': 'Insecure Default Variable Initialization',
        'CWE-454': 'External Initialization of Trusted Variables or Data Stores',
        'CWE-455': 'Non-exit on Failed Initialization',
        'CWE-456': 'Missing Initialization',
        'CWE-457': 'Use of Uninitialized Variable',
        'CWE-458': 'DEPRECATED: Incorrect Initialization',
        'CWE-459': 'Incomplete Cleanup',
        'CWE-46': "Path Equivalence: 'filename ' (Trailing Space)",
        'CWE-460': 'Improper Cleanup on Thrown Exception',
        'CWE-462': 'Duplicate Key in Associative List (Alist)',
        'CWE-463': 'Deletion of Data Structure Sentinel',
        'CWE-464': 'Addition of Data Structure Sentinel',
        'CWE-466': 'Return of Pointer Value Outside of Expected Range',
        'CWE-467': 'Use of sizeof() on a Pointer Type',
        'CWE-468': 'Incorrect Pointer Scaling',
        'CWE-469': 'Use of Pointer Subtraction to Determine Size',
        'CWE-47': "Path Equivalence: ' filename (Leading Space)",
        'CWE-470': 'Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)',
        'CWE-471': 'Modification of Assumed-Immutable Data (MAID)',
        'CWE-472': 'External Control of Assumed-Immutable Web Parameter',
        'CWE-473': 'PHP External Variable Modification',
        'CWE-474': 'Use of Function with Inconsistent Implementations',
        'CWE-475': 'Undefined Behavior for Input to API',
        'CWE-476': 'NULL Pointer Dereference',
        'CWE-477': 'Use of Obsolete Functions',
        'CWE-478': 'Missing Default Case in Switch Statement',
        'CWE-479': 'Unsafe Function Call from a Signal Handler',
        'CWE-48': "Path Equivalence: 'file name' (Internal Whitespace)",
        'CWE-480': 'Use of Incorrect Operator',
        'CWE-481': 'Assigning instead of Comparing',
        'CWE-482': 'Comparing instead of Assigning',
        'CWE-483': 'Incorrect Block Delimitation',
        'CWE-484': 'Omitted Break Statement in Switch',
        'CWE-485': 'Insufficient Encapsulation',
        'CWE-486': 'Comparison of Classes by Name',
        'CWE-487': 'Reliance on Package-level Scope',
        'CWE-488': 'Data Leak Between Sessions',
        'CWE-489': 'Leftover Debug Code',
        'CWE-49': "Path Equivalence: 'filename/' (Trailing Slash)",
        'CWE-491': "Public cloneable() Method Without Final ('Object Hijack')",
        'CWE-492': 'Use of Inner Class Containing Sensitive Data',
        'CWE-493': 'Critical Public Variable Without Final Modifier',
        'CWE-494': 'Download of Code Without Integrity Check',
        'CWE-495': 'Private Array-Typed Field Returned From A Public Method',
        'CWE-496': 'Public Data Assigned to Private Array-Typed Field',
        'CWE-497': 'Exposure of System Data to an Unauthorized Control Sphere',
        'CWE-498': 'Information Leak through Class Cloning',
        'CWE-499': 'Serializable Class Containing Sensitive Data',
        'CWE-5': 'J2EE Misconfiguration: Data Transmission Without Encryption',
        'CWE-50': "Path Equivalence: '//multiple/leading/slash'",
        'CWE-500': 'Public Static Field Not Marked Final',
        'CWE-501': 'Trust Boundary Violation',
        'CWE-502': 'Deserialization of Untrusted Data',
        'CWE-506': 'Embedded Malicious Code',
        'CWE-507': 'Trojan Horse',
        'CWE-508': 'Non-Replicating Malicious Code',
        'CWE-509': 'Replicating Malicious Code (Virus or Worm)',
        'CWE-51': "Path Equivalence: '/multiple//internal/slash'",
        'CWE-510': 'Trapdoor',
        'CWE-511': 'Logic/Time Bomb',
        'CWE-512': 'Spyware',
        'CWE-514': 'Covert Channel',
        'CWE-515': 'Covert Storage Channel',
        'CWE-516': 'DEPRECATED (Duplicate): Covert Timing Channel',
        'CWE-52': "Path Equivalence: '/multiple/trailing/slash//'",
        'CWE-520': '.NET Misconfiguration: Use of Impersonation',
        'CWE-521': 'Weak Password Requirements',
        'CWE-522': 'Insufficiently Protected Credentials',
        'CWE-523': 'Unprotected Transport of Credentials',
        'CWE-524': 'Information Leak Through Caching',
        'CWE-525': 'Information Leak Through Browser Caching',
        'CWE-526': 'Information Leak Through Environmental Variables',
        'CWE-527': 'Exposure of CVS Repository to an Unauthorized Control Sphere',
        'CWE-528': 'Exposure of Core Dump File to an Unauthorized Control Sphere',
        'CWE-529': 'Exposure of Access Control List Files to an Unauthorized Control Sphere',
        'CWE-53': "Path Equivalence: '\\multiple\\internal\\backslash'",
        'CWE-530': 'Exposure of Backup File to an Unauthorized Control Sphere',
        'CWE-531': 'Information Leak Through Test Code',
        'CWE-532': 'Information Leak Through Log Files',
        'CWE-533': 'Information Leak Through Server Log Files',
        'CWE-534': 'Information Leak Through Debug Log Files',
        'CWE-535': 'Information Leak Through Shell Error Message',
        'CWE-536': 'Information Leak Through Servlet Runtime Error Message',
        'CWE-537': 'Information Leak Through Java Runtime Error Message',
        'CWE-538': 'File and Directory Information Exposure',
        'CWE-539': 'Information Leak Through Persistent Cookies',
        'CWE-54': "Path Equivalence: 'filedir\\' (Trailing Backslash)",
        'CWE-540': 'Information Leak Through Source Code',
        'CWE-541': 'Information Leak Through Include Source Code',
        'CWE-542': 'Information Leak Through Cleanup Log Files',
        'CWE-543': 'Use of Singleton Pattern in a Non-thread-safe Manner',
        'CWE-544': 'Failure to Use a Standardized Error Handling Mechanism',
        'CWE-545': 'Use of Dynamic Class Loading',
        'CWE-546': 'Suspicious Comment',
        'CWE-547': 'Use of Hard-coded, Security-relevant Constants',
        'CWE-548': 'Information Leak Through Directory Listing',
        'CWE-549': 'Missing Password Field Masking',
        'CWE-55': "Path Equivalence: '/./' (Single Dot Directory)",
        'CWE-550': 'Information Leak Through Server Error Message',
        'CWE-551': 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization',
        'CWE-552': 'Files or Directories Accessible to External Parties',
        'CWE-553': 'Command Shell in Externally Accessible Directory',
        'CWE-554': 'ASP.NET Misconfiguration: Not Using Input Validation Framework',
        'CWE-555': 'J2EE Misconfiguration: Plaintext Password in Configuration File',
        'CWE-556': 'ASP.NET Misconfiguration: Use of Identity Impersonation',
        'CWE-558': 'Use of getlogin() in Multithreaded Application',
        'CWE-56': "Path Equivalence: 'filedir*' (Wildcard)",
        'CWE-560': 'Use of umask() with chmod-style Argument',
        'CWE-561': 'Dead Code',
        'CWE-562': 'Return of Stack Variable Address',
        'CWE-563': 'Unused Variable',
        'CWE-564': 'SQL Injection: Hibernate',
        'CWE-565': 'Reliance on Cookies without Validation and Integrity Checking',
        'CWE-566': 'Access Control Bypass Through User-Controlled SQL Primary Key',
        'CWE-567': 'Unsynchronized Access to Shared Data',
        'CWE-568': 'finalize() Method Without super.finalize()',
        'CWE-57': "Path Equivalence: 'fakedir/../realdir/filename'",
        'CWE-570': 'Expression is Always False',
        'CWE-571': 'Expression is Always True',
        'CWE-572': 'Call to Thread run() instead of start()',
        'CWE-573': 'Failure to Follow Specification',
        'CWE-574': 'EJB Bad Practices: Use of Synchronization Primitives',
        'CWE-575': 'EJB Bad Practices: Use of AWT Swing',
        'CWE-576': 'EJB Bad Practices: Use of Java I/O',
        'CWE-577': 'EJB Bad Practices: Use of Sockets',
        'CWE-578': 'EJB Bad Practices: Use of Class Loader',
        'CWE-579': 'J2EE Bad Practices: Non-serializable Object Stored in Session',
        'CWE-58': 'Path Equivalence: Windows 8.3 Filename',
        'CWE-580': 'clone() Method Without super.clone()',
        'CWE-581': 'Object Model Violation: Just One of Equals and Hashcode Defined',
        'CWE-582': 'Array Declared Public, Final, and Static',
        'CWE-583': 'finalize() Method Declared Public',
        'CWE-584': 'Return Inside Finally Block',
        'CWE-585': 'Empty Synchronized Block',
        'CWE-586': 'Explicit Call to Finalize()',
        'CWE-587': 'Assignment of a Fixed Address to a Pointer',
        'CWE-588': 'Attempt to Access Child of a Non-structure Pointer',
        'CWE-589': 'Call to Non-ubiquitous API',
        'CWE-59': "Improper Link Resolution Before File Access ('Link Following')",
        'CWE-590': 'Free of Memory not on the Heap',
        'CWE-591': 'Sensitive Data Storage in Improperly Locked Memory',
        'CWE-592': 'Authentication Bypass Issues',
        'CWE-593': 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created',
        'CWE-594': 'J2EE Framework: Saving Unserializable Objects to Disk',
        'CWE-595': 'Comparison of Object References Instead of Object Contents',
        'CWE-596': 'Incorrect Semantic Object Comparison',
        'CWE-597': 'Use of Wrong Operator in String Comparison',
        'CWE-598': 'Information Leak Through Query Strings in GET Request',
        'CWE-599': 'Trust of OpenSSL Certificate Without Validation',
        'CWE-6': 'J2EE Misconfiguration: Insufficient Session-ID Length',
        'CWE-600': 'Failure to Catch All Exceptions in Servlet',
        'CWE-601': "URL Redirection to Untrusted Site ('Open Redirect')",
        'CWE-602': 'Client-Side Enforcement of Server-Side Security',
        'CWE-603': 'Use of Client-Side Authentication',
        'CWE-605': 'Multiple Binds to the Same Port',
        'CWE-606': 'Unchecked Input for Loop Condition',
        'CWE-607': 'Public Static Final Field References Mutable Object',
        'CWE-608': 'Struts: Non-private Field in ActionForm Class',
        'CWE-609': 'Double-Checked Locking',
        'CWE-610': 'Externally Controlled Reference to a Resource in Another Sphere',
        'CWE-611': 'Information Leak Through XML External Entity File Disclosure',
        'CWE-612': 'Information Leak Through Indexing of Private Data',
        'CWE-613': 'Insufficient Session Expiration',
        'CWE-614': "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        'CWE-615': 'Information Leak Through Comments',
        'CWE-616': 'Incomplete Identification of Uploaded File Variables (PHP)',
        'CWE-617': 'Reachable Assertion',
        'CWE-618': 'Exposed Unsafe ActiveX Method',
        'CWE-619': "Dangling Database Cursor ('Cursor Injection')",
        'CWE-62': 'UNIX Hard Link',
        'CWE-620': 'Unverified Password Change',
        'CWE-621': 'Variable Extraction Error',
        'CWE-622': 'Unvalidated Function Hook Arguments',
        'CWE-623': 'Unsafe ActiveX Control Marked Safe For Scripting',
        'CWE-624': 'Executable Regular Expression Error',
        'CWE-625': 'Permissive Regular Expression',
        'CWE-626': 'Null Byte Interaction Error (Poison Null Byte)',
        'CWE-627': 'Dynamic Variable Evaluation',
        'CWE-628': 'Function Call with Incorrectly Specified Arguments',
        'CWE-636': "Not Failing Securely ('Failing Open')",
        'CWE-637': 'Failure to Use Economy of Mechanism',
        'CWE-638': 'Failure to Use Complete Mediation',
        'CWE-639': 'Access Control Bypass Through User-Controlled Key',
        'CWE-64': 'Windows Shortcut Following (.LNK)',
        'CWE-640': 'Weak Password Recovery Mechanism for Forgotten Password',
        'CWE-641': 'Insufficient Filtering of File and Other Resource Names for Executable Content',
        'CWE-642': 'External Control of Critical State Data',
        'CWE-643': "Improper Neutralization of Data within XPath Expressions ('XPath injection')",
        'CWE-644': 'Improper Neutralization of HTTP Headers for Scripting Syntax',
        'CWE-645': 'Overly Restrictive Account Lockout Mechanism',
        'CWE-646': 'Reliance on File Name or Extension of Externally-Supplied File',
        'CWE-647': 'Use of Non-Canonical URL Paths for Authorization Decisions',
        'CWE-648': 'Incorrect Use of Privileged APIs',
        'CWE-649': 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking',
        'CWE-65': 'Windows Hard Link',
        'CWE-650': 'Trusting HTTP Permission Methods on the Server Side',
        'CWE-651': 'Information Leak through WSDL File',
        'CWE-652': 'Improper Neutralization of Data within XQuery Expressions (XQuery Injection)',
        'CWE-653': 'Insufficient Compartmentalization',
        'CWE-654': 'Reliance on a Single Factor in a Security Decision',
        'CWE-655': 'Insufficient Psychological Acceptability',
        'CWE-656': 'Reliance on Security through Obscurity',
        'CWE-657': 'Violation of Secure Design Principles',
        'CWE-66': 'Improper Handling of File Names that Identify Virtual Resources',
        'CWE-662': 'Insufficient Synchronization',
        'CWE-663': 'Use of a Non-reentrant Function in an Unsynchronized Context',
        'CWE-664': 'Improper Control of a Resource Through its Lifetime',
        'CWE-665': 'Improper Initialization',
        'CWE-666': 'Operation on Resource in Wrong Phase of Lifetime',
        'CWE-667': 'Insufficient Locking',
        'CWE-668': 'Exposure of Resource to Wrong Sphere',
        'CWE-669': 'Incorrect Resource Transfer Between Spheres',
        'CWE-67': 'Improper Handling of Windows Device Names',
        'CWE-670': 'Always-Incorrect Control Flow Implementation',
        'CWE-671': 'Lack of Administrator Control over Security',
        'CWE-672': 'Operation on a Resource after Expiration or Release',
        'CWE-673': 'External Influence of Sphere Definition',
        'CWE-674': 'Uncontrolled Recursion',
        'CWE-675': 'Duplicate Operations on Resource',
        'CWE-676': 'Use of Potentially Dangerous Function',
        'CWE-681': 'Incorrect Conversion between Numeric Types',
        'CWE-682': 'Incorrect Calculation',
        'CWE-683': 'Function Call With Incorrect Order of Arguments',
        'CWE-684': 'Failure to Provide Specified Functionality',
        'CWE-685': 'Function Call With Incorrect Number of Arguments',
        'CWE-686': 'Function Call With Incorrect Argument Type',
        'CWE-687': 'Function Call With Incorrectly Specified Argument Value',
        'CWE-688': 'Function Call With Incorrect Variable or Reference as Argument',
        'CWE-69': 'Failure to Handle Windows ::DATA Alternate Data Stream',
        'CWE-691': 'Insufficient Control Flow Management',
        'CWE-693': 'Protection Mechanism Failure',
        'CWE-694': 'Use of Multiple Resources with Duplicate Identifier',
        'CWE-695': 'Use of Low-Level Functionality',
        'CWE-696': 'Incorrect Behavior Order',
        'CWE-697': 'Insufficient Comparison',
        'CWE-698': 'Redirect Without Exit',
        'CWE-7': 'J2EE Misconfiguration: Missing Custom Error Page',
        'CWE-703': 'Failure to Handle Exceptional Conditions',
        'CWE-704': 'Incorrect Type Conversion or Cast',
        'CWE-705': 'Incorrect Control Flow Scoping',
        'CWE-706': 'Use of Incorrectly-Resolved Name or Reference',
        'CWE-707': 'Improper Enforcement of Message or Data Structure',
        'CWE-708': 'Incorrect Ownership Assignment',
        'CWE-71': "Apple '.DS_Store'",
        'CWE-710': 'Coding Standards Violation',
        'CWE-72': 'Improper Handling of Apple HFS+ Alternate Data Stream Path',
        'CWE-73': 'External Control of File Name or Path',
        'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
        'CWE-733': 'Compiler Optimization Removal or Modification of Security-critical Code',
        'CWE-74': "Failure to Sanitize Data into a Different Plane ('Injection')",
        'CWE-749': 'Exposed Dangerous Method or Function',
        'CWE-75': 'Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)',
        'CWE-754': 'Improper Check for Unusual or Exceptional Conditions',
        'CWE-755': 'Improper Handling of Exceptional Conditions',
        'CWE-756': 'Missing Custom Error Page',
        'CWE-757': "Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')",
        'CWE-758': 'Reliance on Undefined, Unspecified, or Implementation-Defined Behavior',
        'CWE-759': 'Use of a One-Way Hash without a Salt',
        'CWE-76': 'Failure to Resolve Equivalent Special Elements into a Different Plane',
        'CWE-760': 'Use of a One-Way Hash with a Predictable Salt',
        'CWE-761': 'Free of Pointer not at Start of Buffer',
        'CWE-762': 'Mismatched Memory Management Routines',
        'CWE-763': 'Release of Invalid Pointer or Reference',
        'CWE-764': 'Multiple Locks of a Critical Resource',
        'CWE-765': 'Multiple Unlocks of a Critical Resource',
        'CWE-766': 'Critical Variable Declared Public',
        'CWE-767': 'Access to Critical Private Variable via Public Method',
        'CWE-768': 'Incorrect Short Circuit Evaluation',
        'CWE-77': 'Improper Sanitization of Special Elements used in a Command (Command Injection)',
        'CWE-770': 'Allocation of Resources Without Limits or Throttling',
        'CWE-771': 'Missing Reference to Active Allocated Resource',
        'CWE-772': 'Missing Release of Resource after Effective Lifetime',
        'CWE-773': 'Missing Reference to Active File Descriptor or Handle',
        'CWE-774': 'Allocation of File Descriptors or Handles Without Limits or Throttling',
        'CWE-775': 'Missing Release of File Descriptor or Handle after Effective Lifetime',
        'CWE-776': "Unrestricted Recursive Entity References in DTDs ('XML Bomb')",
        'CWE-777': 'Regular Expression without Anchors',
        'CWE-778': 'Insufficient Logging',
        'CWE-779': 'Logging of Excessive Data',
        'CWE-78': 'Improper Sanitization of Special Elements used in an OS Command (OS Command Injection)',
        'CWE-780': 'Use of RSA Algorithm without OAEP',
        'CWE-781': 'Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code',
        'CWE-782': 'Exposed IOCTL with Insufficient Access Control',
        'CWE-783': 'Operator Precedence Logic Error',
        'CWE-784': 'Reliance on Cookies without Validation and Integrity Checking in a Security Decision',
        'CWE-785': 'Use of Path Manipulation Function without Maximum-sized Buffer',
        'CWE-786': 'Access of Memory Location Before Start of Buffer',
        'CWE-787': 'Out-of-bounds Write',
        'CWE-788': 'Access of Memory Location After End of Buffer',
        'CWE-789': 'Uncontrolled Memory Allocation',
        'CWE-79': "Failure to Preserve Web Page Structure ('Cross-site Scripting')",
        'CWE-790': 'Improper Filtering of Special Elements',
        'CWE-791': 'Incomplete Filtering of Special Elements',
        'CWE-792': 'Incomplete Filtering of One or More Instances of Special Elements',
        'CWE-793': 'Only Filtering One Instance of a Special Element',
        'CWE-794': 'Incomplete Filtering of Multiple Instances of Special Elements',
        'CWE-795': 'Only Filtering Special Elements at a Specified Location',
        'CWE-796': 'Only Filtering Special Elements Relative to a Marker',
        'CWE-797': 'Only Filtering Special Elements at an Absolute Position',
        'CWE-798': 'Use of Hard-coded Credentials',
        'CWE-799': 'Improper Control of Interaction Frequency',
        'CWE-8': 'J2EE Misconfiguration: Entity Bean Declared Remote',
        'CWE-80': 'Improper Sanitization of Script-Related HTML Tags in a Web Page (Basic XSS)',
        'CWE-804': 'Guessable CAPTCHA',
        'CWE-805': 'Buffer Access with Incorrect Length Value',
        'CWE-806': 'Buffer Access Using Size of Source Buffer',
        'CWE-807': 'Reliance on Untrusted Inputs in a Security Decision',
        'CWE-81': 'Improper Sanitization of Script in an Error Message Web Page',
        'CWE-82': 'Improper Sanitization of Script in Attributes of IMG Tags in a Web Page',
        'CWE-83': 'Improper Neutralization of Script in Attributes in a Web Page',
        'CWE-84': 'Failure to Resolve Encoded URI Schemes in a Web Page',
        'CWE-85': 'Doubled Character XSS Manipulations',
        'CWE-86': 'Improper Neutralization of Invalid Characters in Identifiers in Web Pages',
        'CWE-87': 'Failure to Sanitize Alternate XSS Syntax',
        'CWE-88': 'Argument Injection or Modification',
        'CWE-89': 'Improper Sanitization of Special Elements used in an SQL Command (SQL Injection)',
        'CWE-9': 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods',
        'CWE-90': "Failure to Sanitize Data into LDAP Queries ('LDAP Injection')",
        'CWE-91': 'XML Injection (aka Blind XPath Injection)',
        'CWE-92': 'DEPRECATED: Improper Sanitization of Custom Special Characters',
        'CWE-93': "Failure to Sanitize CRLF Sequences ('CRLF Injection')",
        'CWE-94': "Failure to Control Generation of Code ('Code Injection')",
        'CWE-95': 'Improper Sanitization of Directives in Dynamically Evaluated Code (Eval Injection)',
        'CWE-96': 'Improper Neutralization of Directives in Statically Saved Code (Static Code Injection)',
        'CWE-97': 'Failure to Sanitize Server-Side Includes (SSI) Within a Web Page',
        'CWE-98': 'Improper Control of Filename for Include/Require Statement in PHP Program (PHP File Inclusion)',
        'CWE-99': "Improper Control of Resource Identifiers ('Resource Injection')"
    }

    # Check if the CWE number exists in the dictionary
    if cwe_nr in cwe_descriptions:
        return f"{cwe_nr}: {cwe_descriptions[cwe_nr]}"
    else:
        return "Description not available for CWE-" + cwe_nr


def labelToMargin(label):
    labels = {
        'Vulnerable': '10px',
        'Critical': '22px',
        'Warning': '28px',
        'Checked': '28px'
    }

    if label in labels:
        return labels[label]


def labelToColor(label):
    labels = {
        'Vulnerable': 'red',
        'Critical': 'black',
        'Warning': 'orange',
        'Checked': 'blue'
    }

    if label in labels:
        return labels[label]


def fromOSTypeToFontAwesome(ostype):
    icons = {
        'windows': 'fab fa-windows',
        'solaris': 'fab fa-linux',  # there isn't a better icon on fontawesome :(
        'unix': 'fab fa-linux',  # same here...
        'linux': 'fab fa-linux',
    }

    if ostype.lower() in icons:
        return str(icons[ostype.lower()])
    else:
        return 'fas fa-question'


def nmap_ports_stats(scanfile):
    try:
        oo = xmltodict.parse(open('/opt/xml/' + scanfile, 'r').read())
    except:
        return {'po': 0, 'pc': 0, 'pf': 0}

    r = json.dumps(oo['nmaprun'], indent=4)
    o = json.loads(r)
    debug = {}

    po, pc, pf = 0, 0, 0
    po_str, pc_str, pf_str = "", "", ""

    if 'host' not in o:
        return {'po': 0, 'pc': 0, 'pf': 0}

    iii = 0
    lastaddress = ''
    for ik in o['host']:
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        lastportid = 0

        if '@addr' in i['address']:
            address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    address = ai['@addr']

        if lastaddress == address:
            continue
        lastaddress = address

        if 'ports' in i and 'port' in i['ports']:
            for pobj in i['ports']['port']:
                if type(pobj) is dict:
                    p = pobj
                else:
                    p = i['ports']['port']

                if lastportid == p['@portid']:
                    continue
                else:
                    lastportid = p['@portid']

                if address not in debug:
                    debug[address] = {'portcount': {'pc': {}, 'po': {}, 'pf': {}}}
                debug[address][p['@portid']] = p['state']

                if p['state']['@state'] == 'closed':
                    pc = (pc + 1)
                    debug[address]['portcount']['pc'][iii] = pc
                elif p['state']['@state'] == 'open':
                    po = (po + 1)
                    debug[address]['portcount']['po'][iii] = po
                elif p['state']['@state'] == 'filtered':
                    pf = (pf + 1)
                    debug[address]['portcount']['pf'][iii] = pf
                iii = (iii + 1)

    po_str = html.escape(f"{po}{(4-len(str(po))) * ' '}")
    pc_str = html.escape(f"{pc}{(4-len(str(pc))) * ' '}")
    pf_str = html.escape(f"{pf}{(4-len(str(pf))) * ' '}")

    return {'po': po, 'pc': pc, 'pf': pf, 'debug': json.dumps(debug), "pos": po_str, "pcs:": pc_str, "pfc": pf_str}


def get_cve(scanmd5):
    cvehost = {}
    cvefiles = os.listdir('/opt/notes')
    for cf in cvefiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.cve$', cf)
        if m is not None:
            if m.group(1) not in cvehost:
                cvehost[m.group(1)] = {}

            if m.group(2) not in cvehost[m.group(1)]:
                cvehost[m.group(1)][m.group(2)] = open('/opt/notes/' + cf, 'r').read()

    # cvehost[m.group(1)][m.group(2)][m.group(3)] = open('/opt/notes/'+cf, 'r').read()

    return cvehost


def get_ports_details(scanfile):
    faddress = ""
    oo = xmltodict.parse(open('/opt/xml/' + scanfile, 'r').read())
    out2 = json.dumps(oo['nmaprun'], indent=4)
    o = json.loads(out2)

    r = {'file': scanfile, 'hosts': {}}
    scanmd5 = hashlib.md5(str(scanfile).encode('utf-8')).hexdigest()

    # collect all labels in labelhost dict
    labelhost = {}
    labelfiles = os.listdir('/opt/notes')
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open('/opt/notes/' + lf, 'r').read()

    # collect all notes in noteshost dict
    noteshost = {}
    notesfiles = os.listdir('/opt/notes')
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()

    # collect all cve in cvehost dict
    cvehost = get_cve(scanmd5)

    for ik in o['host']:

        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        hostname = {}
        if 'hostnames' in i and type(i['hostnames']) is dict:
            # hostname = json.dumps(i['hostnames'])
            if 'hostname' in i['hostnames']:
                # hostname += '<br>'
                if type(i['hostnames']['hostname']) is list:
                    for hi in i['hostnames']['hostname']:
                        hostname[hi['@type']] = hi['@name']
                else:
                    hostname[i['hostnames']['hostname']['@type']] = i['hostnames']['hostname']['@name'];

        if i['status']['@state'] == 'up':
            po, pc, pf = 0, 0, 0
            ss, pp, ost = {}, {}, {}
            lastportid = 0

            if '@addr' in i['address']:
                address = i['address']['@addr']
            elif type(i['address']) is list:
                for ai in i['address']:
                    if ai['@addrtype'] == 'ipv4':
                        address = ai['@addr']

            if faddress != "" and faddress != address:
                continue

            addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
            # cpe[address] = {}

            labelout = ''
            if scanmd5 in labelhost:
                if addressmd5 in labelhost[scanmd5]:
                    labelout = labelhost[scanmd5][addressmd5]

            notesout, notesb64, removenotes = '', '', ''
            if scanmd5 in noteshost:
                if addressmd5 in noteshost[scanmd5]:
                    notesb64 = noteshost[scanmd5][addressmd5]
            #		notesout = '<br><a id="noteshost'+str(hostindex)+'" href="#!" onclick="javascript:openNotes(\''+hashlib.md5(str(address).encode('utf-8')).hexdigest()+'\', \''+notesb64+'\');" class="small"><i class="fas fa-comment"></i> contains notes</a>'
            #		removenotes = '<li><a href="#!" onclick="javascript:removeNotes(\''+addressmd5+'\', \''+str(hostindex)+'\');">Remove notes</a></li>'

            cveout = ''
            # cvecount = 0
            if scanmd5 in cvehost:
                if addressmd5 in cvehost[scanmd5]:
                    cveout = json.loads(cvehost[scanmd5][addressmd5])
            #		for cveobj in cvejson:
            #			cvecount = (cvecount + 1)

            # if faddress == "":
            #	r['hosts'][address] = {'hostname':hostname, 'label':labelout, 'notes':notesb64}
            # else:
            r['hosts'][address] = {'ports': [], 'hostname': hostname, 'label': labelout, 'notes': notesb64,
                                   'CVE': cveout}

            if 'ports' in i and 'port' in i['ports']:
                for pobj in i['ports']['port']:
                    if type(pobj) is dict:
                        p = pobj
                    else:
                        p = i['ports']['port']

                    if lastportid == p['@portid']:
                        continue
                    else:
                        lastportid = p['@portid']

                    v, z, e = '', '', ''
                    pp[p['@portid']] = p['@portid']

                    servicename = ''
                    if 'service' in p:
                        ss[p['service']['@name']] = p['service']['@name']

                        if '@version' in p['service']:
                            v = p['service']['@version']

                        if '@product' in p['service']:
                            z = p['service']['@product']

                        if '@extrainfo' in p['service']:
                            e = p['service']['@extrainfo']

                        servicename = p['service']['@name']

                    # if faddress != "":
                    r['hosts'][address]['ports'].append({
                        'port': p['@portid'],
                        'name': servicename,
                        'state': p['state']['@state'],
                        'protocol': p['@protocol'],
                        'reason': p['state']['@reason'],
                        'product': z,
                        'version': v,
                        'extrainfo': e
                    })
    return r
