import sys
sys.path.append("C:\\Users\\administrator\Documents\\fastapi\.venv\Lib\site-packages")

from contextlib import asynccontextmanager

import asyncio
#import aiomysql
import uuid
import datetime
from fastapi import FastAPI, Depends,Request, Response, Query, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, Integer, Text, DateTime, BigInteger, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.future import select


DATABASE_URL= 'mysql+aiomysql://alvaro:test1234@127.0.0.1:3306/cybelinserver'

# Database setup
Base = declarative_base()
engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

Base = declarative_base()

# In-memory data for blacklisted IPs
malicious_ips = set()
malicious_ips_update_interval = 60  # Default fallback interval (in seconds)


async def update_malicious_ips():
    global malicious_ips, malicious_ips_update_interval
    while True:
        try:
            async with async_session() as session:
                # Get the update interval
                query = select(Configurations).where(Configurations.Key == "MaliciousIpCheckIntervalInSeconds")
                result = await session.execute(query)
                config = result.scalar_one_or_none()
                if config and config.Value.isdigit():
                    malicious_ips_update_interval = int(config.Value)

                # Get active malicious IPs
                query = select(BlacklistedIps).where(BlacklistedIps.IsActive == True)
                result = await session.execute(query)
                blacklisted_ips = result.scalars().all()

                # Update the in-memory set of malicious IPs
                malicious_ips = {ip.IpAddress for ip in blacklisted_ips if ip.IpAddress}

        except Exception as e:
            print(f"Error updating malicious IPs: {e}")

        # Wait for the specified interval before updating again
        await asyncio.sleep(malicious_ips_update_interval)


# Models
class Configurations(Base):
    __tablename__ = "configurations"
    Id = Column(Integer, primary_key=True, autoincrement=True)
    Key = Column(Text, nullable=True)
    Value = Column(Text, nullable=True)
    LastUpdated = Column(DateTime(6), nullable=False)


class BlacklistedIps(Base):
    __tablename__ = "blacklistedips"
    Id = Column(Integer, primary_key=True, autoincrement=True)
    IpAddress = Column(Text, nullable=True)
    DateAdded = Column(DateTime(6), nullable=False)
    Reason = Column(Text, nullable=True)
    IsActive = Column(Boolean, nullable=False)


class RequestLog(Base):
    __tablename__ = "requestlogs"
    RequestLogId = Column(BigInteger, primary_key=True, autoincrement=True)
    RequestId = Column(String(36), nullable=False)
    HttpMethod = Column(Text, nullable=True)
    RequestPath = Column(Text, nullable=True)
    QueryString = Column(Text, nullable=True)
    RequestHeaders = Column(Text, nullable=True)
    ClientIp = Column(Text, nullable=True)
    UserAgent = Column(Text, nullable=True)
    RequestTime = Column(DateTime(6), nullable=False)
    HttpVersion = Column(Text, nullable=True)
    RequestBody = Column(Text, nullable=True)


class ResponseLog(Base):
    __tablename__ = "responselogs"
    ResponseLogId = Column(BigInteger, primary_key=True, autoincrement=True)
    RequestId = Column(String(36), nullable=False)
    StatusCode = Column(Integer, nullable=False)
    ResponseHeaders = Column(Text, nullable=True)
    ResponseTime = Column(DateTime(6), nullable=False)
    DurationMs = Column(BigInteger, nullable=False)
    ServerIp = Column(Text, nullable=True)
    ResponseSizeInBytes = Column(BigInteger, nullable=False, default=0)



# Define the lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    task = asyncio.create_task(update_malicious_ips())
    try:
        yield
    finally:
        # Shutdown logic
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

# Create the FastAPI app with the lifespan context
app = FastAPI(lifespan=lifespan)

# FastAPI setup
#app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware to block malicious IPs
@app.middleware("http")
async def block_malicious_ips(request: Request, call_next):
    client_ip = request.client.host
    if client_ip in malicious_ips:
        return Response(content="Forbidden", status_code=403)
    return await call_next(request)


# Middleware to log requests and responses
@app.middleware("http")
async def log_requests_and_responses(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = datetime.datetime.now(datetime.UTC)

    # Read request body
    body = await request.body()
    request_body = body.decode("utf-8") if body else None

    # Log request
    async with async_session() as session:
        async with session.begin():
            request_log = RequestLog(
                RequestId=request_id,
                HttpMethod=request.method,
                RequestPath=str(request.url.path),
                QueryString=str(request.query_params),
                RequestHeaders="",    #str(request.headers),  #For security , to avoid logging JWT
                ClientIp=request.client.host,
                UserAgent=request.headers.get("user-agent", None),
                RequestTime=start_time,
                HttpVersion=request.scope.get("http_version", "1.1"),
                RequestBody=""  # For security =request_body,
            )
            session.add(request_log)

    # Process response
    response = await call_next(request)
    response_body = b"".join([chunk async for chunk in response.body_iterator])

    duration_ms = int((datetime.datetime.now(datetime.UTC) - start_time).total_seconds() * 1000)
    response_size_in_bytes = len(response_body)

    # Log response
    async with async_session() as session:
        async with session.begin():
            response_log = ResponseLog(
                RequestId=request_id,
                StatusCode=response.status_code,
                ResponseHeaders=str(response.headers),
                ResponseTime=datetime.datetime.now(datetime.UTC),
                DurationMs=duration_ms,
                ServerIp="127.0.0.1",  # Replace with actual server IP if needed
                ResponseSizeInBytes=response_size_in_bytes,
            )
            session.add(response_log)

    # Return the response
    return Response(
        content=response_body,
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=response.media_type,
    )


# Test endpoints
@app.get("/")
async def root():
    return {"message": "Hello, world!"}


class Person(BaseModel):
    name: str
    age: int


# Endpoint GET: QueryParameterEndpoint
@app.get("/api/hello", name="QueryParameterEndpoint")
async def query_parameter_endpoint(name: str = Query(...), age: int = Query(...)):
    return {"message": f"Hello {name}, you are {age} years old."}


# Endpoint POST: PostPersonEndpoint
@app.post("/api/person", name="PostPersonEndpoint")
async def post_person_endpoint(person: Person):
    return {"message": f"Received person: {person.name}, Age: {person.age}"}



