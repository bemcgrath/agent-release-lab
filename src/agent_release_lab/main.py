from fastapi import FastAPI

app = FastAPI(title="Agent Release Lab")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
