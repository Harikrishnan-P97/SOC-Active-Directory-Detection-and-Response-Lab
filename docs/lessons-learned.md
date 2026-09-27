# Lessons Learned

## 1. Project Learning Objectives

The SOC Active Directory Detection & Incident Response Lab was built primarily as a hands-on learning environment rather than as a purely theoretical detection project.

The project provided practical experience across the full security monitoring lifecycle:

- Building and administering an Active Directory environment.
- Understanding Windows and Active Directory security telemetry.
- Designing and tuning custom Wazuh detections.
- Validating detections through controlled attack simulations.
- Investigating security alerts and underlying telemetry.
- Writing SOC-level investigation and incident-response playbooks.
- Building security dashboards around meaningful SOC monitoring use cases.
- Connecting detection, investigation, response, and validation into a repeatable workflow.

A central lesson from the project was that these activities are closely connected. Effective detection engineering requires an understanding of the environment generating the telemetry, while effective investigation and response require an understanding of what the detection is intended to identify.

The overall learning cycle became:

**Build → Understand → Simulate → Detect → Investigate → Respond → Validate → Document**

---

## 2. Detection Engineering Lessons

### Detection Engineering Requires More Than Writing Rules

One of the biggest lessons from the project was that writing a Wazuh rule is only one part of detection engineering.

A detection needs to be based on an understanding of:

- The Windows event being generated.
- The relevant event fields.
- The existing Wazuh rules and rule hierarchy.
- The behavior being detected.
- The expected legitimate activity.
- Possible false positives.
- The appropriate MITRE ATT&CK technique.
- How the detection will be validated.

This made detection engineering significantly more involved than initially expected.

### Telemetry Quality Is the Foundation of Detection

A detection can only be as reliable as the telemetry available to it.

During the project, troubleshooting detections often required going below the alert level and examining the underlying Windows or Sysmon event. This demonstrated the importance of understanding exactly what data is being collected before attempting to detect behavior from it.

The project reinforced the relationship:

**Telemetry → Detection Logic → Alert → Investigation**

If the required telemetry is missing, incorrectly configured, or does not contain the expected fields, the detection may never trigger even when the simulated behavior occurs.

### Wazuh Rule Chaining and Tuning

Understanding Wazuh parent and child rules became an important part of the project.

Custom detections frequently depended on existing Wazuh rules to identify the appropriate event before applying additional detection logic. This required understanding:

- Parent rule IDs.
- Child rule conditions.
- Event fields.
- Rule groups.
- Rule levels.
- Regular expressions.
- Rule inheritance and matching behavior.

A major lesson was that a custom rule should be designed around the telemetry and rule chain that actually exists rather than assuming that a particular event will reach the custom rule.

### Validation Is Part of Detection Engineering

The project validated all 42 custom detections using controlled simulations.

This demonstrated that a rule being syntactically valid does not mean that the detection works as intended.

The validation process involved:

1. Generating controlled activity.
2. Verifying Windows/Sysmon telemetry.
3. Checking Wazuh processing.
4. Verifying the resulting alert.
5. Confirming the custom detection rule triggered.
6. Investigating unexpected behavior.
7. Tuning where necessary.
8. Cleaning up the test activity.
9. Documenting the result.

This made validation an integral part of detection development rather than a final optional step.

### ATT&CK Mapping Improves Detection Context

Mapping detections to MITRE ATT&CK techniques helped provide context for what each detection was intended to identify.

The 42 detections covered areas including:

- Authentication
- Account management
- Privilege escalation
- Credential access
- Discovery
- Lateral movement
- Persistence
- Defense evasion
- Impact

This also helped organize the detection portfolio around attacker behaviors rather than individual Windows event IDs alone.

---

## 3. Wazuh / SIEM Lessons

### Alerts and Raw Telemetry Serve Different Purposes

One of the practical lessons from working with Wazuh was understanding the difference between generated alerts and raw telemetry.

The project used:

- `wazuh-alerts-*` for detection and alert-focused analysis.
- `wazuh-archives-*` for examining raw telemetry and investigating events that may not have generated custom alerts.

This distinction became particularly useful when troubleshooting detections.

An event existing in the environment does not necessarily mean that it will appear as a Wazuh alert. Investigation therefore sometimes requires moving from the alert layer back to the underlying telemetry.

### Built-In Rules and Custom Rules Work Together

The project demonstrated the value of using Wazuh's existing ruleset as the foundation for custom detection engineering.

Rather than treating every detection as an isolated rule, custom rules could build on existing Wazuh event identification and then add project-specific detection logic.

This provided a more structured approach to detection development and reduced the need to independently reproduce every low-level event condition.

### Field Mapping Matters

Dashboard development exposed another important SIEM lesson: having telemetry available is not enough if the fields cannot be used correctly by the visualization layer.

Fields such as destination IP, destination port, and DNS query information needed to be correctly recognized by the Wazuh Dashboard/OpenSearch environment before they could be effectively used in visualizations.

This reinforced the importance of checking the complete pipeline:

**Windows/Sysmon → Wazuh → OpenSearch → Dashboard Visualization**

### Troubleshooting Should Follow the Data Pipeline

When a detection or dashboard did not behave as expected, troubleshooting was most effective when performed from the source of the data forward.

The practical approach became:

1. Confirm the activity occurred.
2. Confirm Windows generated the expected event.
3. Check whether Wazuh received and parsed the event.
4. Identify the matching Wazuh rule.
5. Check whether the custom rule matched.
6. Verify the resulting alert.
7. Confirm the data is available to the dashboard.

This was more reliable than assuming the problem was in the final detection or visualization layer.

---

## 4. Active Directory Security Lessons

Building the Active Directory environment from the ground up was itself a significant learning experience.

The project provided hands-on exposure to:

- Domain controllers.
- Active Directory users and groups.
- Privileged groups.
- Service accounts.
- Domain authentication.
- DNS and domain services.
- Windows clients joined to the domain.
- Administrative activity.
- Security event generation.

This provided important context for understanding the behaviors being detected.

### AD Security Is Highly Connected

The project demonstrated that an Active Directory attack rarely fits into a single isolated category.

The detection portfolio covered a progression from:

**Authentication → Credential Access → Discovery → Privilege Escalation → Lateral Movement → Persistence/Defense Evasion → Impact**

Understanding these relationships made it easier to think about detections as parts of an attack lifecycle rather than as unrelated alerts.

### Privileged Activity Requires Specific Monitoring

Monitoring ordinary authentication activity is not sufficient for an AD security monitoring environment.

The project therefore included detections for activities such as:

- Domain Admin membership changes.
- Enterprise Admin membership changes.
- Local Administrator changes.
- Privileged account logons.
- Administrator account enablement.
- Account and computer attribute modifications.

This reinforced the importance of monitoring changes to identities and privileges, not only authentication failures.

### Attack Simulation Improved AD Understanding

Controlled simulations provided a practical way to understand how attacker behaviors appear within the environment.

Activities involving Kerberos, credential access, discovery, remote execution, persistence, and defense evasion could be examined from both sides:

- What the simulated behavior does.
- What telemetry that behavior generates.
- What a SOC analyst would actually see.

That connection was one of the most valuable aspects of building the lab.

---

## 5. Investigation Lessons

### An Alert Is the Starting Point, Not the Conclusion

A major investigation lesson was that a detection alert alone rarely provides the complete answer.

An analyst needs to understand the surrounding context, including:

- User.
- Host.
- Timestamp.
- Source information.
- Process information.
- Event details.
- Related activity.
- Expected versus unexpected behavior.

The investigation therefore moves from:

**Alert → Underlying Event → Context → Related Activity → Assessment**

### Raw Telemetry Is Important During Investigation

The project repeatedly demonstrated why analysts need access to the underlying telemetry.

When a detection did not behave as expected, examining the original Windows/Sysmon event helped identify whether:

- The expected event was generated.
- The event contained the expected fields.
- A different built-in rule matched the event.
- The custom detection logic was too restrictive.
- Additional audit configuration was required.

This troubleshooting process also reflects real investigation behavior: analysts need to understand what actually happened, not just what an alert says happened.

### Investigation and Detection Are Different Activities

Another lesson was that a detection identifies potentially relevant activity, while investigation determines what that activity means in context.

This distinction influenced the development of the investigation and response playbooks.

The detection answers:

> **What behavior was observed?**

The investigation asks:

> **What happened, who or what was involved, and is the activity expected?**

The response process then determines:

> **What actions should be taken?**

---

## 6. SOC Playbook and Response Lessons

Writing SOC-level playbooks was an important part of the project because it required translating technical detections into repeatable analyst actions.

The incident-response workflow was structured around:

**Detection → Investigation → Containment → Eradication → Recovery**

The project included playbooks covering:

- Credential attacks and account compromise.
- AD account and privilege compromise.
- Kerberos and credential theft.
- AD discovery and reconnaissance.
- Lateral movement and remote execution.
- Persistence and defense evasion.
- AD destructive and impact activity.

A key lesson was that a detection becomes more useful when an analyst can immediately understand what to investigate after the alert fires and what response actions are relevant.

This connected the detection engineering work directly to practical SOC operations.

---

## 7. Dashboard Lessons

### Dashboards Should Support SOC Workflows

The dashboard development process showed that a SOC dashboard should not simply display as much telemetry as possible.

Panels should answer useful questions such as:

- How many authentication failures are occurring?
- Are privileged accounts being used?
- Are administrative groups changing?
- Are suspicious processes executing?
- Is PowerShell activity increasing?
- Are discovery or lateral movement behaviors occurring?
- Are persistence mechanisms being created?
- Which events require further investigation?

### Visualization Design Is Part of Detection Engineering

Dashboard design also exposed the importance of choosing the correct:

- Data source.
- Index.
- Field.
- Aggregation.
- Time range.
- Visualization type.
- Label.
- Description.

A technically correct query can still result in a poor SOC visualization if the wrong field or aggregation is used.

### Dashboards Should Reflect the Detection Portfolio

The final dashboard structure was organized around security monitoring areas such as:

- Authentication and Account Monitoring.
- AD Security.
- System and Endpoint Activity.
- Threat Hunting and Lateral Movement.

This helped connect the visualization layer back to the detection engineering and ATT&CK coverage of the project.

---

## 8. Challenges and Solutions

### Challenge: Detection Engineering Was More Complex Than Expected

Detection engineering was one of the hardest parts of the project.

The challenge was not simply creating rule XML. It involved understanding Windows events, Wazuh rule chains, fields, regular expressions, parent rules, ATT&CK mappings, validation behavior, and false-positive considerations.

**Lesson:** Effective detection engineering requires understanding the telemetry and the detection pipeline before writing the final rule.

### Challenge: Detection Validation

Validation was another major challenge.

A detection could appear correct but fail to trigger because the generated event did not match the expected parent rule or because the required Windows audit configuration was not enabled.

**Lesson:** Always verify the complete chain from simulated activity to Windows event to Wazuh rule match to final alert.

### Challenge: Learning Active Directory From the Ground Up

Because the lab also involved learning how to build and operate an AD environment, there was a learning curve around domain configuration, users, groups, authentication, DNS, privileges, and Windows security telemetry.

**Lesson:** Building the environment instead of treating AD as a black box provided a much stronger understanding of the behaviors being detected.

### Challenge: Scheduled Task Telemetry

The scheduled task detection required additional Windows audit configuration before the expected Security event was generated.

**Lesson:** Some detections depend on Windows audit policy configuration. Detection development therefore needs to account for telemetry prerequisites rather than assuming the required event is enabled by default.

### Challenge: Startup Persistence Detection

The Startup Folder detection provided an important example of why understanding Wazuh rule chains matters.

The generated Sysmon Event ID 11 existed, but the event matched a different built-in rule path than the custom rule expected. The investigation of the underlying telemetry revealed why the custom detection did not fire.

**Lesson:** When a custom rule does not trigger, inspect the actual event and the rule that matched it before changing the custom rule.

### Challenge: Dashboard Data and Field Mapping

Some dashboard fields were initially not available for visualization as expected.

**Lesson:** Dashboard troubleshooting sometimes requires checking index mappings and refreshing the available field definitions before changing the query itself.

### Challenge: Separating Raw Telemetry From Alerts

Some Sysmon activity was available in Wazuh archives without being represented as a custom alert.

**Lesson:** Raw telemetry and detection alerts serve different purposes. A SOC analyst needs access to both for effective detection development and investigation.

---

## 9. Future Improvements

### Current Constraints

The current home lab has practical RAM and storage limitations. Because of these hardware constraints, expanding the environment immediately is not practical.

The existing environment therefore serves as the current foundation for continued detection engineering, investigation practice, validation, and documentation.

### Planned Expansion

As resources become available, the lab can be expanded into a broader SOC engineering environment.

Planned areas include:

#### SOAR

Introduce Security Orchestration, Automation and Response capabilities to automate repetitive SOC workflows such as:

- Alert enrichment.
- Investigation steps.
- Notification.
- Containment actions.
- Response tracking.

#### EDR

Introduce endpoint detection and response telemetry to provide deeper visibility into:

- Process execution.
- Endpoint behavior.
- File activity.
- Network activity.
- Detection and response actions.

This would complement the existing Wazuh-based telemetry and provide additional endpoint investigation capabilities.

#### Threat Intelligence

Integrate threat intelligence sources to add external context to observed indicators such as:

- IP addresses.
- Domains.
- Hashes.
- Other relevant indicators.

This would allow the lab to move beyond internal telemetry toward contextualized threat investigation.

#### AI-Assisted Automation

Future iterations may introduce AI-assisted workflows for tasks such as:

- Alert summarization.
- Investigation assistance.
- Event correlation.
- Detection engineering support.
- Playbook assistance.
- Analyst workflow automation.

AI automation would be treated as an enhancement to the existing detection and investigation workflow rather than a replacement for analyst validation.

#### Additional Attack Chains

The lab can be expanded with larger and more realistic multi-stage attack chains.

Future simulations can connect multiple behaviors together, allowing the project to explore how individual detections behave as part of a broader attack sequence.

This would also provide opportunities to develop:

- More advanced detections.
- Stronger correlation logic.
- More realistic attack simulations.
- More detailed investigation workflows.
- More comprehensive response playbooks.

---

## 10. Final Takeaways

The primary outcome of this project was practical experience across the SOC workflow rather than simply producing a collection of Wazuh rules.

The project provided hands-on experience with:

- Building an Active Directory environment.
- Understanding Windows and AD security telemetry.
- Designing custom detections.
- Tuning Wazuh rules.
- Validating detections through controlled simulations.
- Investigating alerts and raw telemetry.
- Building SOC-focused dashboards.
- Writing investigation and incident-response playbooks.
- Connecting detection engineering to operational response.

The most important lesson was that these areas cannot be treated independently.

**Detection engineering depends on telemetry.**

**Investigation depends on understanding the detection and its underlying events.**

**Response depends on understanding the investigation.**

**Validation connects the entire process back to observable evidence.**

The lab therefore evolved into a practical learning environment for the complete:

**Detection → Investigation → Response → Validation**

lifecycle.

The current environment provides the foundation for continued learning. As hardware resources allow, the planned addition of SOAR, EDR, threat intelligence, AI-assisted automation, and more advanced attack chains can extend the lab into a broader SOC engineering and detection research environment.
