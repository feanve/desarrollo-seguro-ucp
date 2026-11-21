# Estudio independiente – Sesión 4

Plazo: antes de la sesión 5 (sábado 21 de noviembre).
Carga estimada: 9 horas (parte de las 64 h de trabajo independiente del curso).

El objetivo es que el gate quede corriendo en el repositorio del equipo, con un PR que bloquea de verdad y una regla que codifica una amenaza del Lab 1 con su prueba. Y preparar el terreno para la sesión 5: asegurar los sistemas de IA que hoy usamos para encontrar y priorizar.

## 1. Lecturas y actividades

| # | Actividad | Horas | Para qué |
|---|---|---|---|
| 1 | Terminar el **Lab 3**: gate instalado y requerido, un PR que el gate bloquea y luego pasa a verde (`auditgate init`, `auditgate scan`). | 3 | El control deja de depender de que alguien se acuerde de correrlo. |
| 2 | [SLSA](https://slsa.dev/spec/v1.0/levels): los niveles de *provenance* y qué garantiza cada uno. | 1 | Saber quién construyó un artefacto, desde qué commit y con qué workflow. |
| 3 | [Sigstore / cosign](https://docs.sigstore.dev/cosign/signing/overview/) (firma *keyless*) y el formato de SBOM ([CycloneDX](https://cyclonedx.org/) o [SPDX](https://spdx.dev/)). | 1 | Firmar sin manejar llaves privadas, y la lista de materiales que salva del próximo Log4Shell. |
| 4 | [OpenSSF Scorecard](https://github.com/ossf/scorecard) y las prácticas de un repo endurecido (SHA pinning, permisos mínimos, 2FA). | 1 | El checklist de un pipeline que no es superficie de ataque. |
| 5 | **Codificar la regla** del Lab 3: una amenaza del top 5 del Lab 1 vuelta regla Semgrep con dos fixtures y su prueba. | 2 | El salto de arreglar el bug a impedir el patrón. Entregable del Lab 3. |
| 6 | Leer sobre riesgos de IA: [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) y qué es *prompt injection*. | 1 | Puente a la sesión 5: el triage de IA que usamos hoy es, mañana, objeto de estudio. |
| | **Total** | **9** | |

Además: integrar el **Entregable 1** del proyecto (secciones 1 a 3) en el repositorio del equipo, si aún no quedó listo en clase.

## 2. Preguntas de autoevaluación

1. ¿Por qué un pipeline con doce escáneres en `continue-on-error: true` no es un control de seguridad? ¿Qué cambia cuando uno de ellos es *required status check*?
2. Auditgate bloquea «solo lo nuevo». ¿Qué problema de adopción resuelve eso frente a un gate que bloquea toda la deuda existente? ¿Qué riesgo introduce (la deuda vieja nunca se arregla) y cómo lo mitigarían?
3. ¿Por qué fijar una GitHub Action por SHA y no por tag (`@v4`)? Relacionen con el incidente de tj-actions (2025).
4. Un secreto comiteado y luego borrado con `git rm`: ¿por qué no basta? ¿Cuál es la respuesta correcta y por qué?
5. ¿Qué garantiza la *provenance* SLSA que un simple hash del artefacto no garantiza?
6. Firma *keyless* con cosign: si no hay llave privada guardada, ¿con qué identidad se firma y por cuánto tiempo existe esa credencial?
7. ¿Qué es Workload Identity Federation (WIF) y por qué elimina la necesidad de guardar una llave de larga vida del modelo en los Secrets del repo?
8. En Auditgate, el agente de IA comenta pero nunca marca checks. Si el triage se equivoca y dice «falso positivo» de algo real, ¿entra el PR? ¿Y si dice «verdadero positivo» de algo falso? Expliquen por qué el diseño es seguro en ambos casos.
9. Diferencia entre arreglar un bug y codificar una regla. Den un ejemplo de su proyecto donde el patrón generalizable sea distinto de la línea concreta que falló.
10. Una regla Semgrep sin fixture de caso seguro, ¿qué riesgo tiene en un equipo real? Relacionen con por qué el gate exige que las pruebas de la regla pasen.

## 3. Referencias

- Auditgate: <https://github.com/Jawy77/auditgate>
- GitHub Security Lab, *Find → Extract → Codify → Scale*: <https://securitylab.github.com/>
- SLSA, *Supply-chain Levels for Software Artifacts*: <https://slsa.dev/>
- Sigstore / cosign: <https://docs.sigstore.dev/>
- SBOM — CycloneDX: <https://cyclonedx.org/> · SPDX: <https://spdx.dev/>
- OpenSSF Scorecard: <https://github.com/ossf/scorecard>
- OSV — Open Source Vulnerabilities: <https://osv.dev/>
- Semgrep, escribir reglas: <https://semgrep.dev/docs/writing-rules/overview>
- OWASP Top 10 for LLM Applications: <https://genai.owasp.org/llm-top-10/>
