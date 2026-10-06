import time, sys, shutil, glob, os
from playwright.sync_api import sync_playwright
OUT = "labvideo"
STYLE = open("../../memgraph-resources/style.gss", encoding="utf-8").read()
Q_DAY = "\n".join([
    "MATCH (a:host)-[r]->(b:host)",
    "WHERE r.time >= localDateTime('2020-09-19T03:00:00')",
    "  AND r.time <  localDateTime('2020-09-19T04:00:00')",
    "  AND NOT a.name CONTAINS ':'",
    "RETURN a, r, b;",
])
Q_PATH = "\n".join([
    "MATCH path = (attacker:host {name: '194.61.24.102'})-[*..4]->(victim:host {name: 'DESKTOP-SDN1RPT'})",
    "WHERE ALL(i IN range(0, size(relationships(path)) - 2)",
    "WHERE relationships(path)[i].time < relationships(path)[i+1].time)",
    "RETURN path ORDER BY length(path) LIMIT 5;",
])
W, H = 1400, 820
shutil.rmtree(OUT, ignore_errors=True); os.makedirs(OUT)

def editor(page):
    loc = page.locator(".monaco-editor .view-lines >> visible=true").first
    loc.wait_for(state="visible", timeout=60000)
    return loc

def type_query(page, q, delay=0.03):
    editor(page).click(); page.keyboard.press("Control+A"); page.keyboard.press("Delete")
    for ch in q:
        page.keyboard.insert_text(ch); time.sleep(delay)
    page.keyboard.press("Escape"); time.sleep(0.3)
    page.evaluate("q => { const eds = monaco.editor.getEditors().filter(e => e.hasTextFocus()); (eds.length ? eds : monaco.editor.getEditors()).slice(0,1).forEach(e => e.getModel().setValue(q)); }", q)
    time.sleep(0.4)

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": W, "height": H}, record_video_dir=OUT, record_video_size={"width": W, "height": H})
    page = ctx.new_page()
    page.goto("http://localhost:3000", wait_until="networkidle")
    time.sleep(2.5)
    page.get_by_role("button", name="Connect now").click()
    time.sleep(3)
    page.keyboard.press("Escape"); time.sleep(0.8)
    editor(page)
    page.evaluate("() => monaco.editor.getEditors().forEach(e => e.updateOptions({autoClosingBrackets: 'never', autoClosingQuotes: 'never', quickSuggestions: false, suggestOnTriggerCharacters: false}))")
    def tab(name):
        for _ in range(3):
            page.get_by_text(name, exact=True).first.click(force=True); time.sleep(1.2)
            if page.locator(".monaco-editor .view-lines >> visible=true").count(): return
    # 1. the hour of the intrusion
    type_query(page, Q_DAY)
    page.keyboard.press("Control+Enter"); time.sleep(6)
    page.screenshot(path=os.path.join(OUT, "s1_day.png"))
    # style
    try:
        tab("Graph Style editor")
        page.evaluate("st => { const m = monaco.editor.getModels().find(m => m.getValue().startsWith('// A palette')) || monaco.editor.getModels()[1]; m.setValue(st); }", STYLE); time.sleep(1.5)
        page.get_by_role("button", name="Apply").first.click(force=True); time.sleep(4)
        page.screenshot(path=os.path.join(OUT, "s2_style.png"))
        tab("Cypher editor")
    except Exception as e:
        print("style step skipped:", e)
    # 2. temporal path between the attacker and the workstation
    type_query(page, Q_PATH)
    page.keyboard.press("Control+Enter"); time.sleep(8)
    page.screenshot(path=os.path.join(OUT, "s3_path.png"))
    time.sleep(3)
    ctx.close(); b.close()
print("video:", glob.glob(os.path.join(OUT, "*.webm")))
