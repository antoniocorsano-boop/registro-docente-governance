# GOV-AUTO-01 — Ammissione automatica

La registrazione autorizzata del candidato avviene mediante una richiesta di modifica del solo file admission/candidate.json nel repository di governance. Il manifesto contiene PR, ramo, commit, base, parent e tree esatti; non contiene identificativi di esecuzione, credenziali, indirizzi di rete o istruzioni eseguibili.

Integrare il manifesto con procedura ordinaria sul main protetto solo dopo che le qualificazioni applicative sono concluse. L'evento push sul manifesto avvia automaticamente il workflow GOV-AUTO-01. Nessun avvio manuale ricorrente, nessuna schedulazione continua, nessun accesso al codice candidato. La politica RD-12-23-V1 mantiene 12 workflow, 23 job e 14 impronte di file di qualificazione; se cambiano, HOLD e revisione autorizzata della politica, non accettazione automatica.

Se il candidato è già attestato con provenienza verificata e politica compatibile, il job privilegiato viene saltato. Per un candidato nuovo, l'ambiente GOV-ADMISSION conserva l'approvazione umana e le credenziali già esistenti. Dopo approvazione, rilettura completa, emissione unica, rilettura dell'attestazione e revoca. Nessun nuovo permesso, nessun merge o rilascio automatico. Eventi non autorizzati, evidenze incomplete, esiti incerti e rate limit producono HOLD; non ripetere indiscriminatamente.

I sorgenti e test ereditati in qualified/ sono estratti byte per byte dal workflow qualificato GOV-ADMISSION-07, blob 35bfb8093c3694008ed925c6ca9841c51ab22bcf, main 30bd8389d880196af1dd235ab3811319565e4a46, e verificati dal manifesto SHA256SUMS prima di ogni esecuzione. Il workflow precedente rimane invariato e condivide il gruppo di concorrenza. I nuovi test di raccordo non sostituiscono il collaudo ufficiale.

Prima attivazione: il manifesto indica deliberatamente #416 già attestata. Esito atteso: ALREADY_ATTESTED, nessun accesso al secret, nessuna nuova attestazione. Il ramo di emissione per candidati futuri rimane subordinato all'approvazione dell'ambiente e alla sua prima evidenza effettiva. R1/R2/R3 e decisione di rilascio restano separati.
