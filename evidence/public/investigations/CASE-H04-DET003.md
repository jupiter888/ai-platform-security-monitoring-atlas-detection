# CASE-H04-DET003 — Sustained Inference Querying

**Status:** Awaiting analyst review.

## Observed Activity

- Actual inference requests verified: 36.
- Rule: DET-003.
- Finding ID: `1f12d2382ef8e2fb9ad5f47e9070ff9884a00ba824b551309ca2e3d95971534b`.
- The finding was queued, stored by the receiver, and acknowledged.

## Interpretation

Telemetry establishes sustained authenticated querying. It does not
establish intent or downstream use of model outputs.

The controlled runner separately identifies this as authorized
adversarial emulation and records replica evaluation results.
Approved bulk processing is a demonstrated alternative explanation.

## Timeline

| UTC timestamp | Observation | Evidence reference |
|---|---|---|
| 2026-11-13T18:43:39.592764+00:00 | inference_observed | `55bc8a2d-ebcf-4322-9485-2e0f1d6c3582` |
| 2026-11-13T18:43:43.106023+00:00 | inference_observed | `37783976-d826-4424-8563-2de9440151ee` |
| 2026-11-13T18:43:46.620457+00:00 | inference_observed | `36340ad5-3414-4842-8f69-d049aad0b8ff` |
| 2026-11-13T18:43:50.134096+00:00 | inference_observed | `303595c4-1af2-4adb-90fb-a0497444ae23` |
| 2026-11-13T18:43:53.650483+00:00 | inference_observed | `be69a87e-5757-47d3-a861-081bb16380e8` |
| 2026-11-13T18:43:57.164996+00:00 | inference_observed | `0ab178ed-8c94-40e7-9663-de6c2a1f4dac` |
| 2026-11-13T18:44:00.678971+00:00 | inference_observed | `754aa90d-e5a9-4d3f-9c85-6e784028120f` |
| 2026-11-13T18:44:04.193149+00:00 | inference_observed | `402a5919-bcef-4f55-944f-0b27ce3ae2a7` |
| 2026-11-13T18:44:07.709899+00:00 | inference_observed | `697dd9a9-85ec-4a4f-99aa-9a1e2daa9278` |
| 2026-11-13T18:44:11.224248+00:00 | inference_observed | `2951a2ce-47ad-4c2b-90bf-33d5ad3bc146` |
| 2026-11-13T18:44:14.738800+00:00 | inference_observed | `7a361749-0e8a-4021-b101-b469b9b061a1` |
| 2026-11-13T18:44:18.252885+00:00 | inference_observed | `64828802-88dc-4da6-9fdb-382ef1d43045` |
| 2026-11-13T18:44:21.767418+00:00 | inference_observed | `b6f9a180-5510-48e1-b6b3-6dddd62cda35` |
| 2026-11-13T18:44:25.283025+00:00 | inference_observed | `002e9280-b5d4-47ac-8975-a16c9d291b9d` |
| 2026-11-13T18:44:28.798597+00:00 | inference_observed | `bf38af6c-0d04-40b4-8210-872c3b0cd998` |
| 2026-11-13T18:44:32.313479+00:00 | inference_observed | `21608f65-9459-4857-b99c-f892840f5c09` |
| 2026-11-13T18:44:35.829614+00:00 | inference_observed | `58e35870-c3d9-4c8e-877e-0fd094f0e807` |
| 2026-11-13T18:44:39.345498+00:00 | inference_observed | `80c79885-2538-455d-873b-46c845526563` |
| 2026-11-13T18:44:42.859056+00:00 | inference_observed | `ad8146c3-9985-4200-b43d-f502f01ad132` |
| 2026-11-13T18:44:46.375430+00:00 | inference_observed | `c0e77f83-dd4b-46e4-9a06-6eb5108e5570` |
| 2026-11-13T18:44:49.889923+00:00 | inference_observed | `6b5b6f7e-8195-4bae-8724-e080ed24f953` |
| 2026-11-13T18:44:53.406136+00:00 | inference_observed | `eadf682f-0fcb-49d4-9cfd-43afb165bf52` |
| 2026-11-13T18:44:56.919598+00:00 | inference_observed | `ae74b4d0-1269-4ded-960a-1592e4038227` |
| 2026-11-13T18:45:00.433803+00:00 | inference_observed | `860e486e-8622-4722-90f2-4a2138b84c81` |
| 2026-11-13T18:45:03.949879+00:00 | inference_observed | `9b516942-c351-4aa2-b6f1-70fbc11621a1` |
| 2026-11-13T18:45:07.465571+00:00 | inference_observed | `49cfc0ba-e2b1-42ff-ade4-ff961dc87050` |
| 2026-11-13T18:45:10.982701+00:00 | inference_observed | `a4a59aa5-ce53-4171-968c-1b9db8387275` |
| 2026-11-13T18:45:14.498819+00:00 | inference_observed | `3316b8c9-b9e7-45cd-927e-e7739146209f` |
| 2026-11-13T18:45:18.014480+00:00 | inference_observed | `d7bfe182-bf57-4088-bce4-b19da7dbd3d7` |
| 2026-11-13T18:45:21.529532+00:00 | inference_observed | `e36f1aba-af2b-4ece-a818-603f6e6336b7` |
| 2026-11-13T18:45:21.529532+00:00 | threshold_crossed | `30 successful requests within 180 seconds` |
| 2026-11-13T18:45:25.042574+00:00 | inference_observed | `2b42fd81-c44f-4a83-a4e1-1f6ca75e2675` |
| 2026-11-13T18:45:25.169815+00:00 | finding_detected | `1f12d2382ef8e2fb9ad5f47e9070ff9884a00ba824b551309ca2e3d95971534b` |
| 2026-11-13T18:45:25.169815+00:00 | finding_queued | `1f12d2382ef8e2fb9ad5f47e9070ff9884a00ba824b551309ca2e3d95971534b` |
| 2026-11-13T18:45:25.190147+00:00 | receiver_stored | `1f12d2382ef8e2fb9ad5f47e9070ff9884a00ba824b551309ca2e3d95971534b` |
| 2026-11-13T18:45:25.192350+00:00 | outbox_acknowledged | `1f12d2382ef8e2fb9ad5f47e9070ff9884a00ba824b551309ca2e3d95971534b` |
| 2026-11-13T18:45:28.558057+00:00 | inference_observed | `e5e64402-9992-4294-8644-3f36c4a9ca0a` |
| 2026-11-13T18:45:32.074123+00:00 | inference_observed | `95415115-2f3f-46f4-80c8-f0dfe99cff4e` |
| 2026-11-13T18:45:35.586436+00:00 | inference_observed | `141d021a-cac7-4483-b8e5-1c36385afb60` |
| 2026-11-13T18:45:39.101687+00:00 | inference_observed | `b12e257e-0f94-47c2-a355-c04d62470d6c` |
| 2026-11-13T18:45:42.620431+00:00 | inference_observed | `f7eb3d4b-4699-48db-8b46-d9d803f44e4c` |

## Response

No containment action has been authorized or executed by this script.
Review caller authorization, approved activity, and supporting evidence.

## Evidence

- [Structured case](CASE-H04-DET003.json)
- [Held-out run](../query-volume-holdout-run.json)
- [Held-out assessment](../query-volume-holdout-assessment.json)
- [Monitor coverage](../holdout-monitor.jsonl)

## Limitations

- This is a controlled local laboratory case.
- Scenario intent comes from exercise ground truth.
- The timeline is not tamper-evident or independently time-attested.
- Volume alone does not justify automatic containment.
