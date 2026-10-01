@Library('xmos_jenkins_shared_library@v0.33.0') _

getApproval()

pipeline {
  agent {
    label 'x86_64 && linux'
  }
  environment {
    REPO = 'test_support'
    VIEW = getViewName(REPO)
  }
  options {
    skipDefaultCheckout()
  }
  stages {
    stage('Get view') {
      steps {
        xcorePrepareSandbox("${VIEW}", "${REPO}")
      }
    }
    stage('Library checks') {
      steps {
        xcoreLibraryChecks("${REPO}")
      }
    }
    
  }
  post {
    success {
      updateViewfiles()
    }
    cleanup {
      cleanWs()
    }
  }
}
