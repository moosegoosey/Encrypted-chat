# Start from a small official Python image.
FROM python:3.12-slim

# All following commands run inside /app in the container.
WORKDIR /app

# Install dependencies first. Docker caches each step, so this slow step
# is skipped on rebuilds unless requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only what the server needs.
COPY server.py .

# Run as a normal user instead of root (limits damage if the app is compromised).
RUN useradd --create-home appuser
USER appuser

# Inside a container the server must listen on all interfaces, not just localhost.
ENV HOST=0.0.0.0
ENV PORT=8765
EXPOSE 8765

CMD ["python", "server.py"]