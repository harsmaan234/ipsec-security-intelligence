"""Generate executive and technical PDF reports from analysis evidence."""

from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _value(data: dict[str, Any] | None, key: str, default: Any = "N/A") -> Any:
    if not isinstance(data, dict):
        return default

    value = data.get(key)
    return default if value is None else value


def _text(value: Any) -> str:
    if value is None:
        return "N/A"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    return str(value)


def _percent(value: Any) -> str:
    if value is None:
        return "N/A"

    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return _text(value)


def _score(value: Any) -> str:
    if value is None:
        return "NOT ASSESSED"

    try:
        return f"{float(value):.1f}/100"
    except (TypeError, ValueError):
        return _text(value)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=24,
            leading=28,
            alignment=TA_CENTER,
            spaceAfter=8 * mm,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#555555"),
            spaceAfter=10 * mm,
        ),
        "h1": ParagraphStyle(
            "ReportH1",
            parent=base["Heading1"],
            fontSize=16,
            leading=20,
            spaceBefore=6 * mm,
            spaceAfter=4 * mm,
        ),
        "h2": ParagraphStyle(
            "ReportH2",
            parent=base["Heading2"],
            fontSize=12,
            leading=15,
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=base["BodyText"],
            fontSize=9,
            leading=13,
            spaceAfter=2 * mm,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=base["BodyText"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#555555"),
        ),
        "finding": ParagraphStyle(
            "Finding",
            parent=base["BodyText"],
            fontSize=8.5,
            leading=12,
            spaceAfter=2 * mm,
        ),
    }


def _header_footer(canvas: Any, document: Any) -> None:
    canvas.saveState()

    width, height = A4

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#666666"))

    canvas.drawString(
        18 * mm,
        10 * mm,
        "Sentinel IPsec Intelligence",
    )

    canvas.drawRightString(
        width - 18 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


def _section_title(title: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(title, styles["h1"])


def _table(
    rows: list[list[Any]],
    widths: list[float],
) -> Table:
    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#E8EEF5"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#17202A"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "LEADING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor("#C7D0D9"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    return table


def _summary_rows(analysis: dict[str, Any]) -> list[list[str]]:
    score = analysis.get("score") or {}
    assessment = analysis.get("assessment") or {}
    coverage = assessment.get("coverage") or {}

    return [
        ["Metric", "Value"],
        ["Security score", _score(score.get("score"))],
        ["Risk level", _text(score.get("risk_level"))],
        ["Assessment coverage", _percent(coverage.get("percentage"))],
        [
            "Scoring coverage",
            _percent(score.get("scoring_coverage")),
        ],
        [
            "Assessed controls",
            _text(coverage.get("assessed")),
        ],
        [
            "Applicable controls",
            _text(coverage.get("total_applicable")),
        ],
        [
            "Findings",
            _text(assessment.get("finding_count", 0)),
        ],
    ]


def _ipsec_rows(analysis: dict[str, Any]) -> list[list[str]]:
    ike = analysis.get("ike") or {}
    proposal = ike.get("selected_proposal") or {}
    esp = analysis.get("esp") or {}

    return [
        ["Property", "Observed value", "Provenance"],
        [
            "IKE protocol",
            _text(ike.get("protocol")),
            "OBSERVED",
        ],
        [
            "IKE version",
            _text(ike.get("version")),
            "OBSERVED",
        ],
        [
            "Encryption",
            _text(proposal.get("encryption")),
            "OBSERVED",
        ],
        [
            "PRF",
            _text(proposal.get("prf")),
            "OBSERVED",
        ],
        [
            "Integrity",
            _text(proposal.get("integrity")),
            "OBSERVED",
        ],
        [
            "DH group",
            _text(proposal.get("dh_group")),
            "OBSERVED",
        ],
        [
            "ESP packets",
            _text(esp.get("packet_count")),
            "OBSERVED",
        ],
    ]


def _findings_flow(
    analysis: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    story: list[Any] = []

    assessment = analysis.get("assessment") or {}
    findings = assessment.get("findings") or []

    if not findings:
        story.append(
            Paragraph(
                "No findings were produced by the currently assessed "
                "deterministic security rules.",
                styles["body"],
            )
        )
        return story

    for index, finding in enumerate(findings, start=1):
        severity = _text(finding.get("severity")).upper()
        name = _text(finding.get("name"))
        description = _text(finding.get("description"))
        recommendation = _text(finding.get("recommendation"))

        story.append(
            Paragraph(
                (
                    f"<b>{index}. [{severity}] {name}</b><br/>"
                    f"{description}<br/>"
                    f"<b>Recommendation:</b> {recommendation}"
                ),
                styles["finding"],
            )
        )

    return story


def _traffic_rows(analysis: dict[str, Any]) -> list[list[str]]:
    intelligence = analysis.get("traffic_intelligence") or {}
    flows = intelligence.get("flows") or []

    rows = [
        [
            "Flow",
            "Endpoints",
            "AI class",
            "Confidence",
            "Metadata",
        ]
    ]

    for index, flow in enumerate(flows, start=1):
        features = flow.get("features") or {}
        classification = flow.get("classification") or {}
        metadata = flow.get("metadata_exposure") or {}

        source = _text(features.get("flow_source"))
        destination = _text(features.get("flow_destination"))

        confidence = classification.get("confidence")
        confidence_text = (
            f"{float(confidence) * 100:.1f}%"
            if confidence is not None
            else "N/A"
        )

        rows.append(
            [
                str(index),
                f"{source} → {destination}",
                _text(classification.get("predicted_class")),
                confidence_text,
                _text(metadata.get("overall_exposure")),
            ]
        )

    return rows


def _traffic_detail_flow(
    flow: dict[str, Any],
    index: int,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    features = flow.get("features") or {}
    classification = flow.get("classification") or {}
    explanation = classification.get("explanation") or {}
    metadata = flow.get("metadata_exposure") or {}

    elements: list[Any] = []

    elements.append(
        Paragraph(
            f"Flow {index}: "
            f"{_text(features.get('flow_source'))} → "
            f"{_text(features.get('flow_destination'))}",
            styles["h2"],
        )
    )

    elements.append(
        _table(
            [
                ["Feature", "Value"],
                ["Packet count", _text(features.get("packet_count"))],
                ["Total bytes", _text(features.get("total_bytes"))],
                [
                    "Mean packet size",
                    _text(features.get("mean_packet_size")),
                ],
                [
                    "Mean interarrival",
                    _text(features.get("mean_interarrival")),
                ],
                [
                    "Flow duration",
                    _text(features.get("flow_duration")),
                ],
                [
                    "Packets/second",
                    _text(features.get("packets_per_second")),
                ],
                [
                    "Bytes/second",
                    _text(features.get("bytes_per_second")),
                ],
                [
                    "Direction ratio",
                    _text(features.get("direction_ratio")),
                ],
                [
                    "Burst count",
                    _text(features.get("burst_count")),
                ],
            ],
            [70 * mm, 100 * mm],
        )
    )

    elements.append(Spacer(1, 3 * mm))

    confidence = classification.get("confidence")
    confidence_text = (
        f"{float(confidence) * 100:.1f}%"
        if confidence is not None
        else "N/A"
    )

    elements.append(
        Paragraph(
            (
                "<b>AI traffic classification</b><br/>"
                f"Prediction: {_text(classification.get('predicted_class'))}<br/>"
                f"Confidence: {confidence_text}<br/>"
                f"Model: {_text(classification.get('model_version'))}<br/>"
                "Provenance: INFERRED"
            ),
            styles["body"],
        )
    )

    top_features = explanation.get("top_features") or []

    if top_features:
        rows = [["Feature", "Value", "SHAP contribution", "Direction"]]

        for item in top_features:
            rows.append(
                [
                    _text(item.get("feature")),
                    _text(item.get("value")),
                    _text(item.get("shap_value")),
                    _text(item.get("direction")),
                ]
            )

        elements.append(
            Paragraph(
                (
                    "<b>Explainability</b><br/>"
                    "SHAP TreeExplainer feature contributions used to "
                    "explain the model prediction. These explanations do "
                    "not alter the prediction or security score."
                ),
                styles["body"],
            )
        )

        elements.append(
            _table(
                rows,
                [50 * mm, 35 * mm, 45 * mm, 40 * mm],
            )
        )

    elements.append(Spacer(1, 3 * mm))

    elements.append(
        Paragraph(
            (
                "<b>Metadata exposure assessment</b><br/>"
                f"Overall exposure: {_text(metadata.get('overall_exposure'))}<br/>"
                f"Findings: {_text(metadata.get('finding_count', 0))}<br/>"
                f"Summary: {_text(metadata.get('summary'))}<br/>"
                "Provenance: ASSESSED"
            ),
            styles["body"],
        )
    )

    return elements


def _build_document(
    story: list[Any],
    title: str,
) -> bytes:
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=title,
        author="Sentinel IPsec Intelligence",
    )

    document.build(
        story,
        onFirstPage=_header_footer,
        onLaterPages=_header_footer,
    )

    return buffer.getvalue()


def generate_executive_report(analysis: dict[str, Any]) -> bytes:
    """Generate a concise executive security report."""
    styles = _styles()
    pcap = analysis.get("pcap") or {}

    story: list[Any] = [
        Spacer(1, 8 * mm),
        Paragraph(
            "IPsec Security Assessment",
            styles["title"],
        ),
        Paragraph(
            "Executive Report",
            styles["subtitle"],
        ),
        Paragraph(
            f"<b>Capture:</b> {_text(pcap.get('filename'))}",
            styles["body"],
        ),
        Spacer(1, 5 * mm),
        _table(
            _summary_rows(analysis),
            [70 * mm, 100 * mm],
        ),
        _section_title("IPsec Intelligence", styles),
        _table(
            _ipsec_rows(analysis),
            [50 * mm, 80 * mm, 40 * mm],
        ),
        _section_title("Key Findings", styles),
    ]

    story.extend(_findings_flow(analysis, styles))

    intelligence = analysis.get("traffic_intelligence") or {}
    flow_count = intelligence.get("flow_count", 0)

    story.append(_section_title("Traffic Intelligence", styles))
    story.append(
        Paragraph(
            f"Analyzed bidirectional traffic flows: {_text(flow_count)}.",
            styles["body"],
        )
    )

    traffic_rows = _traffic_rows(analysis)

    if len(traffic_rows) > 1:
        story.append(
            _table(
                traffic_rows,
                [15 * mm, 55 * mm, 35 * mm, 30 * mm, 35 * mm],
            )
        )
    else:
        story.append(
            Paragraph(
                "No traffic flow classification results were produced.",
                styles["body"],
            )
        )

    story.append(
        Paragraph(
            (
                "<b>Assessment interpretation:</b> The security score and "
                "risk level are calculated from the evidence available in "
                "this capture. Assessment coverage indicates how many "
                "applicable controls have sufficient evidence for assessment; "
                "scoring coverage indicates how much of the configured scoring "
                "policy contributes to the reported score. An unassessed "
                "control is not treated as secure."
            ),
            styles["small"],
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Provenance:</b> OBSERVED values come directly from "
                "protocol or packet evidence. INFERRED values are produced "
                "by the traffic classification model. ASSESSED values are "
                "deterministic security conclusions. AI classification "
                "does not decrypt protected payloads."
            ),
            styles["small"],
        )
    )

    return _build_document(
        story,
        "IPsec Security Assessment - Executive Report",
    )


def generate_technical_report(analysis: dict[str, Any]) -> bytes:
    """Generate a detailed technical security report."""
    styles = _styles()
    pcap = analysis.get("pcap") or {}
    ike = analysis.get("ike") or {}
    esp = analysis.get("esp") or {}
    assessment = analysis.get("assessment") or {}
    score = analysis.get("score") or {}
    intelligence = analysis.get("traffic_intelligence") or {}

    story: list[Any] = [
        Spacer(1, 10 * mm),
        Paragraph(
            "IPsec Security Assessment",
            styles["title"],
        ),
        Paragraph(
            "Technical Report",
            styles["subtitle"],
        ),
        Paragraph(
            f"<b>Capture:</b> {_text(pcap.get('filename'))}",
            styles["body"],
        ),
        _section_title("Assessment Summary", styles),
        _table(
            _summary_rows(analysis),
            [70 * mm, 100 * mm],
        ),
        _section_title("IPsec / IKE Evidence", styles),
        _table(
            _ipsec_rows(analysis),
            [50 * mm, 80 * mm, 40 * mm],
        ),
        Paragraph(
            (
                f"IKE exchanges observed: "
                f"{len(ike.get('exchanges') or [])}."
            ),
            styles["body"],
        ),
        _section_title("ESP Evidence", styles),
        _table(
            [
                ["Property", "Value", "Provenance"],
                [
                    "ESP observed",
                    _text(esp.get("observed")),
                    "OBSERVED",
                ],
                [
                    "Packet count",
                    _text(esp.get("packet_count")),
                    "OBSERVED",
                ],
                [
                    "Directions",
                    _text(len(esp.get("directions") or [])),
                    "OBSERVED",
                ],
                [
                    "Sequence analysis",
                    Paragraph(
                        _text(
                            (esp.get("sequence_analysis") or {}).get("note")
                        ),
                        styles["small"],
                    ),
                    "OBSERVED",
                ],
            ],
            [50 * mm, 100 * mm, 40 * mm],
        ),
        _section_title("Security Findings", styles),
    ]

    story.extend(_findings_flow(analysis, styles))

    story.append(PageBreak())
    story.append(_section_title("Controls and Coverage", styles))

    controls = assessment.get("controls") or []

    if controls:
        control_rows = [
            [
                Paragraph("Control", styles["small"]),
                Paragraph("Category", styles["small"]),
                Paragraph("Status", styles["small"]),
                Paragraph("Reason", styles["small"]),
            ]
        ]

        for control in controls:
            control_rows.append(
                [
                    Paragraph(
                        _text(control.get("name") or control.get("control_id")),
                        styles["small"],
                    ),
                    Paragraph(
                        _text(control.get("category")),
                        styles["small"],
                    ),
                    Paragraph(
                        _text(control.get("status")),
                        styles["small"],
                    ),
                    Paragraph(
                        _text(control.get("reason")),
                        styles["small"],
                    ),
                ]
            )

        story.append(
            _table(
                control_rows,
                [45 * mm, 35 * mm, 30 * mm, 70 * mm],
            )
        )
    else:
        story.append(
            Paragraph(
                "No assessment controls were returned.",
                styles["body"],
            )
        )

    story.append(_section_title("Score Breakdown", styles))

    category_scores = score.get("category_scores") or {}

    if category_scores:
        score_rows = [
            [
                "Category",
                "Score",
                "Weight",
                "Findings",
                "Assessed controls",
            ]
        ]

        for category, category_data in category_scores.items():
            score_rows.append(
                [
                    category,
                    _score(category_data.get("score")),
                    _text(category_data.get("weight")),
                    _text(category_data.get("finding_count")),
                    _text(
                        category_data.get("assessed_control_count")
                    ),
                ]
            )

        story.append(
            _table(
                score_rows,
                [45 * mm, 30 * mm, 30 * mm, 30 * mm, 45 * mm],
            )
        )

    story.append(_section_title("Traffic Intelligence", styles))

    flows = intelligence.get("flows") or []

    if flows:
        for index, flow in enumerate(flows, start=1):
            story.extend(
                _traffic_detail_flow(
                    flow,
                    index,
                    styles,
                )
            )
    else:
        story.append(
            Paragraph(
                "No traffic intelligence flows were returned.",
                styles["body"],
            )
        )

    story.append(_section_title("Assessment Limitations", styles))
    story.append(
        Paragraph(
            (
                "This report reflects only evidence available in the "
                "analyzed capture and the deterministic rules configured "
                "for this version of the platform. NOT_ASSESSED controls "
                "are not treated as secure. Traffic classification is a "
                "machine-learning inference from encrypted-flow metadata; "
                "the protected payload is not decrypted by the classifier."
            ),
            styles["body"],
        )
    )

    return _build_document(
        story,
        "IPsec Security Assessment - Technical Report",
    )
