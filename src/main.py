import argparse
import ast
import os
import sys
import time
from ai_engine import *
from tree_sitter_parsing import TreeSitterProjectAudit as ProjectAudit
from dataset_manager import load_dataset, Project
from planning.planning import Planning
from sqlalchemy import create_engine
from dao import CacheManager, ProjectTaskMgr
import pandas as pd
from openpyxl import Workbook, load_workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from res_processor.res_processor import ResProcessor

import dotenv
dotenv.load_dotenv()

# Configure logging system
from logging_config import setup_logging, get_logger, log_section_start, log_section_end, log_step, log_error, log_warning, log_success, log_data_info



def scan_project(project, db_engine):
    logger = get_logger("scan_project")
    scan_start_time = time.time()
    
    log_section_start(logger, "Project scan", f"Project ID: {project.id}, path: {project.path}")
    
    # 1. parsing projects  
    log_step(logger, "Parse project with Tree-sitter", f"Project path: {project.path}")
    parsing_start = time.time()
    
    project_audit = ProjectAudit(project.id, project.path, db_engine)
    project_audit.parse()
    
    parsing_duration = time.time() - parsing_start
    log_success(logger, "Project parsing completed", f"Duration: {parsing_duration:.2f}s")
    log_data_info(logger, "Parsed functions", len(project_audit.functions_to_check))
    log_data_info(logger, "Call trees", len(project_audit.call_trees))
    log_data_info(logger, "Call graphs", len(project_audit.call_graphs))
    
    # 1.5 initialize RAG processor (optional)
    log_step(logger, "Initialize RAG processor")
    rag_processor = None
    try:
        from context.rag_processor import RAGProcessor
        rag_start = time.time()
        
        rag_processor = RAGProcessor(
            project_audit, 
            "./src/codebaseQA/lancedb", 
            project.id
        )
        
        rag_duration = time.time() - rag_start
        log_success(logger, "RAG processor initialized", f"Duration: {rag_duration:.2f}s")
        log_data_info(logger, "Functions from Tree-sitter used for RAG", len(project_audit.functions_to_check))
        log_data_info(logger, "Document chunks used for RAG", len(project_audit.chunks))
        log_data_info(logger, "Call trees used for relational RAG", len(project_audit.call_trees))
        log_data_info(logger, "Integrated call graphs", len(project_audit.call_graphs))
        
        # Display call graph statistics if available
        if project_audit.call_graphs:
            call_graph_stats = project_audit.get_call_graph_statistics()
            log_data_info(logger, "Call graph statistics", call_graph_stats)
        
    except ImportError as e:
        log_warning(logger, "RAG processor unavailable, using simplified functionality")
        print(e)
        logger.debug(f"ImportError details: {e}")
    except Exception as e:
        log_error(logger, "Failed to initialize RAG processor", e)
        rag_processor = None
    

    
    # 2. planning & scanning - directly using project_audit
    log_step(logger, "Create task manager")
    project_taskmgr = ProjectTaskMgr(project.id, db_engine) 
    log_success(logger, "Task manager created")
    
    # create planning processor with project_audit
    log_step(logger, "Create planning processor")
    planning = Planning(project_audit, project_taskmgr)
    log_success(logger, "Planning processor created")
    
    # initialize planning RAG features if available
    if rag_processor:
        log_step(logger, "Initialize planning RAG capabilities")
        planning.initialize_rag_processor("./src/codebaseQA/lancedb", project.id)
        log_success(logger, "Planning RAG capabilities initialized")
    
    # create AI engine
    log_step(logger, "Create AI engine")
    lancedb_table = rag_processor.db if rag_processor else None
    lancedb_table_name = rag_processor.table_name if rag_processor else f"lancedb_{project.id}"
    logger.info(f"LanceDB table name: {lancedb_table_name}")
    
    engine = AiEngine(planning, project_taskmgr, lancedb_table, lancedb_table_name, project_audit)
    log_success(logger, "AI engine created")
    
    # execute planning and scanning
    log_step(logger, "Execute project planning")
    planning_start = time.time()
    engine.do_planning()
    planning_duration = time.time() - planning_start
    log_success(logger, "Project planning completed", f"Duration: {planning_duration:.2f}s")
    
    log_step(logger, "Execute vulnerability scan (reasoning)")
    scan_start = time.time()
    engine.do_scan()
    scan_duration = time.time() - scan_start
    log_success(logger, "Vulnerability scan (reasoning) completed", f"Duration: {scan_duration:.2f}s")
    
    # deduplicate after reasoning before validation
    log_step(logger, "Post-reasoning deduplication")
    dedup_start = time.time()
    ResProcessor.perform_post_reasoning_deduplication(project.id, db_engine, logger)
    dedup_duration = time.time() - dedup_start
    log_success(logger, "Post-reasoning deduplication completed", f"Duration: {dedup_duration:.2f}s")
    
    total_scan_duration = time.time() - scan_start_time
    log_section_end(logger, "Project scan", total_scan_duration)

    return lancedb_table, lancedb_table_name, project_audit

def check_function_vul(engine, lancedb, lance_table_name, project_audit):
    """Execute vulnerability checks using project_audit data directly."""
    logger = get_logger("check_function_vul")
    check_start_time = time.time()
    
    log_section_start(logger, "Vulnerability verification", f"Project ID: {project_audit.project_id}")
    
    log_step(logger, "Create project task manager")
    project_taskmgr = ProjectTaskMgr(project_audit.project_id, engine)
    log_success(logger, "Project task manager created")
    
    # directly create vulnerability checker with project_audit
    log_step(logger, "Initialize vulnerability checker")
    from validating import VulnerabilityChecker
    checker = VulnerabilityChecker(project_audit, lancedb, lance_table_name)
    log_success(logger, "Vulnerability checker initialized")
    
    # execute vulnerability validation
    log_step(logger, "Run vulnerability verification")
    validation_start = time.time()
    checker.check_function_vul(project_taskmgr)
    validation_duration = time.time() - validation_start
    log_success(logger, "Vulnerability verification completed", f"Duration: {validation_duration:.2f}s")
    
    total_check_duration = time.time() - check_start_time
    log_section_end(logger, "Vulnerability verification", total_check_duration)


if __name__ == '__main__':
    # initialize logging
    log_file_path = setup_logging()
    main_logger = get_logger("main")
    main_start_time = time.time()
    
    main_logger.info("🎯 Program startup parameters:")
    main_logger.info(f"   Python version: {sys.version}")
    main_logger.info(f"   Working directory: {os.getcwd()}")
    main_logger.info(f"   Environment variables loaded")

    switch_production_or_test = 'test' # test / direct_excel
    main_logger.info(f"Run mode: {switch_production_or_test}")

    if switch_production_or_test == 'direct_excel':
        log_section_start(main_logger, "Direct Excel generation mode")
        
        start_time = time.time()
        
        # initialize database
        log_step(main_logger, "Initialize database connection")
        db_url_from = os.environ.get("DATABASE_URL")
        main_logger.info(f"Database URL: {db_url_from}")
        engine = create_engine(db_url_from)
        log_success(main_logger, "Database connection created")
        
        # set project parameters
        project_id = 'token0902'  # existing project ID
        main_logger.info(f"Target project ID: {project_id}")
        
        # generate Excel directly
        log_step(main_logger, "Generate Excel report via ResProcessor")
        excel_start = time.time()
        ResProcessor.generate_excel("./output_direct.xlsx", project_id, engine)
        excel_duration = time.time() - excel_start
        log_success(main_logger, "Excel report generated", f"Duration: {excel_duration:.2f}s, file: ./output_direct.xlsx")
        
        total_duration = time.time() - start_time
        log_section_end(main_logger, "Direct Excel generation mode", total_duration)
        
    elif switch_production_or_test == 'test':
        log_section_start(main_logger, "Test mode execution")
        
        start_time=time.time()
        
        # initialize database
        log_step(main_logger, "Initialize database connection")
        db_url_from = os.environ.get("DATABASE_URL")
        main_logger.info(f"Database URL: {db_url_from}")
        engine = create_engine(db_url_from)
        log_success(main_logger, "Database connection created")
        
        # load dataset
        log_step(main_logger, "Load dataset")
        dataset_base = "./src/dataset/agent-v1-c4"
        main_logger.info(f"Dataset path: {dataset_base}")
        projects = load_dataset(dataset_base)
        log_success(main_logger, "Dataset loaded", f"Found {len(projects)} projects")
 
        # set project parameters
        project_id = 'moonlith3'  # existing project ID
        project_path = ''
        main_logger.info(f"Target project ID: {project_id}")
        project = Project(project_id, projects[project_id])
        log_success(main_logger, "Project object created")
        
        # check scan mode
        scan_mode = os.getenv("SCAN_MODE","SPECIFIC_PROJECT")
        main_logger.info(f"Scan mode: {scan_mode}")
        
        cmd = 'detect_vul'
        main_logger.info(f"Executing command: {cmd}")
        
        if cmd == 'detect_vul':
            # run project scan
            lancedb, lance_table_name, project_audit = scan_project(project, engine)
            
            if scan_mode in ["COMMON_PROJECT", "PURE_SCAN", "CHECKLIST", "COMMON_PROJECT_FINE_GRAINED"]:
                main_logger.info(f"Scan mode '{scan_mode}' requires vulnerability verification")
                check_function_vul(engine, lancedb, lance_table_name, project_audit)
            else:
                main_logger.info(f"Scan mode '{scan_mode}' skips vulnerability verification")

        # total execution time
        end_time=time.time()
        total_duration = end_time-start_time
        log_success(main_logger, "All scanning tasks completed", f"Total duration: {total_duration:.2f}s")
        
        # generate Excel report
        log_step(main_logger, "Generate Excel report")
        excel_start = time.time()
        ResProcessor.generate_excel("./output.xlsx", project_id, engine)
        excel_duration = time.time() - excel_start
        log_success(main_logger, "Excel report generated", f"Duration: {excel_duration:.2f}s, file: ./output.xlsx")
        
        log_section_end(main_logger, "Test mode execution", time.time() - main_start_time)
