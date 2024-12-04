CREATE DATABASE CybelinServer;
USE CybelinServer;

-- Tabla BlacklistedIps
CREATE TABLE BlacklistedIps (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    IpAddress TEXT NULL,
    DateAdded DATETIME(6) NOT NULL,
    Reason TEXT NULL,
    IsActive BOOLEAN NOT NULL
);

-- Tabla Configurations
CREATE TABLE Configurations (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    `Key` TEXT NULL,
    `Value` TEXT NULL,
    LastUpdated DATETIME(6) NOT NULL
);

-- Tabla RequestLogs
CREATE TABLE RequestLogs (
    RequestLogId BIGINT AUTO_INCREMENT PRIMARY KEY,
    RequestId CHAR(36) NOT NULL, -- Para UUID
    HttpMethod TEXT NULL,
    RequestPath TEXT NULL,
    QueryString TEXT NULL,
    RequestHeaders TEXT NULL,
    ClientIp TEXT NULL,
    UserAgent TEXT NULL,
    RequestTime DATETIME(6) NOT NULL,
    HttpVersion TEXT NULL,
    RequestBody TEXT NULL
);

-- Tabla ResponseLogs
CREATE TABLE ResponseLogs (
    ResponseLogId BIGINT AUTO_INCREMENT PRIMARY KEY,
    RequestId CHAR(36) NOT NULL, -- Para UUID
    StatusCode INT NOT NULL,
    ResponseHeaders TEXT NULL,
    ResponseTime DATETIME(6) NOT NULL,
    DurationMs BIGINT NOT NULL,
    ServerIp TEXT NULL,
    ResponseSizeInBytes BIGINT NOT NULL DEFAULT 0
);

-- Procedimiento GetLogsAfterDate
DELIMITER $$
CREATE PROCEDURE GetLogsAfterDate(IN RequestTimeFilter DATETIME(6))
BEGIN
    SELECT 
        rl.RequestLogId,
        rl.RequestId,
        rl.HttpMethod,
        rl.RequestPath,
        rl.QueryString,
        rl.RequestHeaders,
        rl.ClientIp,
        rl.UserAgent,
        rl.RequestTime,
        rl.HttpVersion,
        rl.RequestBody,
        resl.ResponseLogId,
        resl.StatusCode,
        resl.ResponseHeaders,
        resl.ResponseTime,
        resl.DurationMs,
        resl.ServerIp,
        resl.ResponseSizeInBytes
    FROM 
        RequestLogs rl
    LEFT JOIN 
        ResponseLogs resl
    ON 
        rl.RequestId = resl.RequestId
    WHERE 
        rl.RequestTime >= RequestTimeFilter
    ORDER BY 
        rl.RequestLogId;
END$$
DELIMITER ;

-- Procedimiento GetLogsFilteredByTimeAndClientIp
DELIMITER $$
CREATE PROCEDURE GetLogsFilteredByTimeAndClientIp(
    IN RequestTimeFilter DATETIME(6),
    IN ClientIp TEXT
)
BEGIN
    SELECT 
        r.RequestLogId,
        r.RequestId,
        r.HttpMethod,
        r.RequestPath,
        r.QueryString,
        r.RequestHeaders,
        r.ClientIp,
        r.UserAgent,
        r.RequestTime,
        r.HttpVersion,
        r.RequestBody,
        res.ResponseLogId,
        res.StatusCode,
        res.ResponseHeaders,
        res.ResponseTime,
        res.DurationMs,
        res.ServerIp,
        res.ResponseSizeInBytes
    FROM 
        RequestLogs r
    LEFT JOIN 
        ResponseLogs res
    ON 
        r.RequestId = res.RequestId
    WHERE 
        r.RequestTime >= RequestTimeFilter
        AND r.ClientIp = ClientIp
    ORDER BY 
        r.RequestLogId;
END$$
DELIMITER ;

-- Insertar un registro en Configurations
INSERT INTO Configurations (`Key`, `Value`, LastUpdated) 
VALUES ('MaliciousIpCheckIntervalInSeconds', '60', '2024-10-12 04:15:57');
