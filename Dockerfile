# Step 1: Use an official, lightweight Python runtime as a parent image
FROM python:3.11-slim

# Step 2: Set environment variables to optimize Python behavior inside the container
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Step 3: Set the working directory inside the container
WORKDIR /app

# Step 4: Install system dependencies (needed for packages like psycopg2 or cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Step 5: Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Step 6: Copy the rest of your Django project application code
COPY . /app/

# Step 7: Expose port 8000 (the standard port Django/Gunicorn uses)
EXPOSE 8000

# Step 8: Run database migrations and start Gunicorn web server
# Replace 'myproject' with your actual Django project directory name (where wsgi.py lives)
CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn myproject.wsgi:application --bind 0.0.0.0:8000"]
