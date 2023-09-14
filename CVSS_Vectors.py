# V2_PATTERN = "AV:([L|A|N])/AC:(H|M|L)/Au:([M|S|N])/C:([N|P|C])/I:([N|P|C])/A:([N|P|C])"


def _parse_vector(vector_string):
    fields = {}
    parts = vector_string.split("/")
    for part in parts:
        field, value = part.split(":")
        fields[field] = value
    return fields


class Cvss3vector:
    def __init__(self, vector_string):
        self.vector_string = vector_string
        self.fields = _parse_vector(self.vector_string)
        self.version = 0
        self.attack_vector = ""
        self.att_complexity = ""
        self.privileges_required = ""
        self.user_interaction = ""
        self.scope = ""
        self.confidentiality = ""
        self.integrity = ""
        self.availability = ""
        self.mapping = {
            "AV": {
                "N": "Network",
                "A": "Adjacent Network",
                "L": "Local",
                "P": "Physical"
            },
            "AC": {
                "H": "High",
                "L": "Low"
            },
            "PR": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "UI": {
                "N": "None",
                "R": "Required"
            },
            "S": {
                "U": "Unchanged",
                "C": "Changed"
            },
            "C": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "I": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "A": {
                "N": "None",
                "L": "Low",
                "H": "High"
            }
        }
        self.get_text()

    def get_text(self):
        for key in self.fields.keys():
            if key == "CVSS":
                self.version = self.fields['CVSS']
            elif key == "AV":
                self.attack_vector = self.mapping.get('AV', '').get(self.fields['AV'], '')
            elif key == "AC":
                self.att_complexity = self.mapping.get('AC', '').get(self.fields['AC'], '')
            elif key == "PR":
                self.privileges_required = self.mapping.get('PR', '').get(self.fields['PR'], '')
            elif key == "UI":
                self.user_interaction = self.mapping.get('UI', '').get(self.fields['UI'], '')
            elif key == "S":
                self.scope = self.mapping.get('S', '').get(self.fields['S'], '')
            elif key == "C":
                self.confidentiality = self.mapping.get('C', '').get(self.fields['C'], '')
            elif key == "I":
                self.integrity = self.mapping.get('I', '').get(self.fields['I'], '')
            elif key == "A":
                self.availability = self.mapping.get('A', '').get(self.fields['A'], '')

    def __str__(self):
        td_style = 'style="padding:0; margin:0; border: none;"'
        tr_style = 'style="border: none;"'

        overview = f'<table style="border-collapse: collapse;">' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>CVSS Version</td>' \
                   f'<td {td_style}>{self.version}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Attack Vector (AV)</td>' \
                   f'<td {td_style}>{self.attack_vector}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Attack Complexity (AC)</td>' \
                   f'<td {td_style}>{self.att_complexity}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Privileges Required (PR)</td>' \
                   f'<td {td_style}>{self.privileges_required}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>User Interaction (UI)</td>' \
                   f'<td {td_style}>{self.user_interaction}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Scope (S)</td>' \
                   f'<td {td_style}>{self.scope}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Confidentiality Impact (C)</td>' \
                   f'<td {td_style}>{self.confidentiality}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Integrity Impact (I)</td>' \
                   f'<td {td_style}>{self.integrity}</td>' \
                   f'</tr>' \
                   f'<tr {tr_style}>' \
                   f'<td {td_style}>Availability Impact (A)</td>' \
                   f'<td {td_style}>{self.availability}</td>' \
                   f'</tr>' \
                   f'</table>'

        return overview


class Cvss2Vector:
    def __init__(self, cvss_vector_string):
        self.vector_string = cvss_vector_string
        self.fields = _parse_vector(self.vector_string)
        self.version = 0
        self.access_vector = ""
        self.access_complexity = ""
        self.authentication = ""
        self.confidentiality_impact = ""
        self.integrity_impact = ""
        self.availability_impact = ""
        self.mapping = {
            "AV": {
                "N": "Network",
                "A": "Adjacent Network",
                "L": "Local"
            },
            "AC": {
                "H": "High",
                "M": "Medium",
                "L": "Low"
            },
            "Au": {
                "N": "None",
                "M": "Multiple",
                "S": "Single"
            },
            "C": {
                "N": "None",
                "P": "Partial",
                "C": "Complete"
            },
            "I": {
                "N": "None",
                "P": "Partial",
                "C": "Complete"
            },
            "A": {
                "N": "None",
                "P": "Partial",
                "C": "Complete"
            }
        }
        self.get_text()

    def get_text(self):
        for key in self.fields.keys():
            if key == "CVSS":
                self.version = self.fields['CVSS']
            elif key == "AV":
                self.access_vector = self.mapping.get('AV', '').get(self.fields['AV'], '')
            elif key == "AC":
                self.access_complexity = self.mapping.get('AC', '').get(self.fields['AC'], '')
            elif key == "Au":
                self.authentication = self.mapping.get('Au', '').get(self.fields['Au'], '')
            elif key == "C":
                self.confidentiality_impact = self.mapping.get('C', '').get(self.fields['C'], '')
            elif key == "I":
                self.integrity_impact = self.mapping.get('I', '').get(self.fields['I'], '')
            elif key == "A":
                self.availability_impact = self.mapping.get('A', '').get(self.fields['A'], '')

    def __str__(self):

        td_style = 'style="padding:0; margin:0; border: none;"'
        tr_style = 'style="border: none;"'

        cvss_2_html_table = f'<table style="border-collapse: collapse;">' \
                            f'<tr {tr_style}>' \
                            f'<td {td_style}>Access Vector (AV)</td>' \
                            f'<td {td_style}>{self.access_vector}</td>' \
                            f'</tr>' \
                            f'<tr {tr_style}>' \
                            f'<td {td_style}>Access Complexity (AC)</td>' \
                            f'<td {td_style}>{self.access_complexity}</td>' \
                            f'</tr>' \
                            f'<tr {tr_style}>' \
                            f'<td {td_style}>Authentication (Au)</td>' \
                            f'<td {td_style}>{self.authentication}</td>' \
                            f'</tr>' \
                            f'<tr {tr_style}>' \
                            f'<td {td_style}>Confidentiality Impact (C)</td>' \
                            f'<td {td_style}>{self.confidentiality_impact}</td>' \
                            f'</tr>' \
                            f'<tr {tr_style}>' \
                            f'<td {td_style}>Integrity Impact (I)</td>' \
                            f'<td {td_style}>{self.integrity_impact}</td>' \
                            f'</tr>' \
                            f'<tr {tr_style}>' \
                            f'<td {td_style}>Availability Impact (A)</td>' \
                            f'<td {td_style}>{self.availability_impact}</td>' \
                            f'</tr>' \
                            f'</table>'

        return cvss_2_html_table

    def __repr__(self):
        return f"CVSS_vector(cvss_vec='{self.access_vector}/{self.access_complexity}/" \
               f"{self.authentication}/{self.confidentiality_impact}/" \
               f"{self.integrity_impact}/{self.availability_impact}')"
